"""
Reentrancy vulnerability detection pipeline for Solidity smart contracts.

Two parallel data representations are built per function:
  - "emb" (embedding matrix, shape (100, 300)): sequential Word2Vec/FastText
    token embeddings, consumed by the BiLSTM branch.
  - "att" (attention map, shape (100, 100, 3)): a square token-by-token
    matrix combining semantic similarity and token co-occurrence, consumed
    by the U-Net branch.

Both representations are built together in process_batch_with_categorization_for_unet()
and stored under CACHE_DIR_UNET with "emb_"/"att_" filename prefixes.

Three training strategies are implemented:
  - train_LSTM()          : BiLSTM branch trained alone.
  - test_unet_branch_alone(): U-Net branch trained alone.
  - train_UNET_LSTM()     : the two branches trained jointly end-to-end
                             (concatenated features) - kept for reference;
                             found to underperform the two branches trained
                             separately, due to gradient interference.
  - train_stacking_ensemble(): the recommended approach - both branches are
                             trained independently, frozen, and their output
                             probabilities are combined by a small meta-model.
"""

import json
import re
import os
from pathlib import Path
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import load_model
from gensim.models import Word2Vec, FastText
import pickle
import PreProcessTools
import numpy as np
from tensorflow.keras import backend as K
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from tensorflow.keras.models import Sequential, Model
from tensorflow.keras.layers import (
    Bidirectional, LSTM, Dropout, Dense, Input,
    Conv2D, MaxPooling2D, UpSampling2D, concatenate, SpatialDropout2D,
    GlobalAveragePooling2D, GlobalMaxPooling2D,
)
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.optimizers import Adam
import matplotlib.pyplot as plt

# =============================================================================
# Global configuration
# =============================================================================

# Populated by getResultVulnarable() for basic bookkeeping of how many
# contracts each analysis tool reported on and how long it took.
duration_stat = {}
count = {}
output = {}

batch_size = 1000
output_name = 'icse20'
vector_length = 300

# Matrix size used for every function representation: (sequence_length, vector_length)
# for the embedding branch, and (sequence_length, sequence_length, 3) for the
# attention-map branch. 100 tokens per function matches the base paper's
# reported embedding matrix size.
sequence_length = 100

# Window size (in tokens) used when building the co-occurrence channel of
# the attention map: two tokens are marked as "co-occurring" if they are
# at most this many positions apart.
co_occurrence_window = 3

tools = ['mythril', 'slither', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify', 'honeybadger']

target_vulnerability_integer_overflow = 'Integer Overflow'
target_vulnerability_reentrancy = 'Reentrancy'
target_vulnerability_transaction_order_dependence = 'Transaction order dependence'
target_vulnerability_timestamp_dependency = 'timestamp'
target_vulnerability_callstack_depth_attack = 'Depth Attack'
target_vulnerability_integer_underflow = 'Integer Underflow'

target_vulner = target_vulnerability_reentrancy

# --- Environment paths ---
# Active configuration: Google Colab / Linux runtime.
ROOT = '/content/smartbugs-wild-with-content-and-result'

# Alternative for local development outside Colab:
# ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

# Dataset for the BiLSTM+U-Net pipeline (both "emb_" and "att_" files).
CACHE_DIR_UNET = os.path.join(ROOT, 'vectorcollections_img')

# Global (corpus-wide) Word2Vec/FastText models. Building embeddings from a
# single shared model (instead of one model per function) gives every token
# a stable, comparable vector across all functions - required for the U-Net
# branch to generalize token-level patterns (e.g. "call" near "value")
# across different contracts.
GLOBAL_FASTTEXT_PATH = os.path.join(ROOT, 'global_fasttext_model.bin')
GLOBAL_WORD2VEC_PATH = os.path.join(ROOT, 'global_word2vec_model.bin')

# Contract source directory:
# PATH = f"{ROOT}\\contracts\\"   # Windows-style, for local testing
PATH = os.path.join(ROOT, 'contracts')  # Linux / Colab
os.chdir(PATH)


# =============================================================================
# Loss function
# =============================================================================

def focal_loss(alpha=0.25, gamma=2.0):
    """Focal loss (as used by the base paper) to counter class imbalance
    between vulnerable and safe functions."""
    def loss(y_true, y_pred):
        epsilon = K.epsilon()
        y_pred = K.clip(y_pred, epsilon, 1. - epsilon)
        pt = y_true * y_pred + (1 - y_true) * (1 - y_pred)
        return -K.mean(alpha * K.pow(1. - pt, gamma) * K.log(pt))
    return loss


def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    return sentence in text


# =============================================================================
# Vulnerability-label extraction from static-analysis tool output
# =============================================================================

def getResultVulnarable(contract_name, target_vulnerability):
    """
    Read every configured tool's result.json for a given contract and check
    whether any of them flagged `target_vulnerability`. Returns (found, lines)
    where `lines` are the reported source line numbers for that vulnerability.

    NOTE: verify this path before relying on results - path construction
    must include a separator between ROOT and "results" (e.g. via
    os.path.join(ROOT, "results", ...)); a missing separator here would
    silently make every contract look "safe" for every tool.
    """
    total_duration = 0
    res = False
    lines = []
    for tool in tools:
        path_result = os.path.join(f"{ROOT}results", tool, output_name, contract_name, 'result.json')
        if not os.path.exists(path_result):
            continue
        with open(path_result, 'r', encoding='utf-8') as fd:
            try:
                data = json.load(fd)
            except Exception:
                continue
            if tool not in duration_stat:
                duration_stat[tool] = 0
            if tool not in count:
                count[tool] = 0
            count[tool] += 1
            duration_stat[tool] += data['duration']
            total_duration += data['duration']
            if contract_name not in output:
                output[contract_name] = {'tools': {}, 'lines': set(), 'nb_vulnerabilities': 0}
            output[contract_name]['tools'][tool] = {'vulnerabilities': {}, 'categories': {}}
            if data['analysis'] is None:
                continue

            if tool == 'mythril':
                analysis = data['analysis']
                if analysis['issues'] is not None:
                    for result in analysis['issues']:
                        vulnerability = result['title'].strip()
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True
                            lines.extend([result['lineno']])

            elif tool in ('oyente', 'osiris', 'honeybadger'):
                for analysis in data['analysis']:
                    if analysis['errors'] is not None:
                        for result in analysis['errors']:
                            vulnerability = result['message'].strip()
                            if is_sentence_in_text(target_vulnerability, vulnerability):
                                res = True
                                lines.extend([result['line']])

            elif tool == 'manticore':
                for analysis in data['analysis']:
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True
                            lines.extend([result['line']])

            elif tool == 'maian':
                for vulnerability in data['analysis']:
                    if data['analysis'][vulnerability]:
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True
                            # No line numbers are reported by this tool.

            elif tool == 'securify':
                for f in data['analysis']:
                    analysis = data['analysis'][f]['results']
                    for vulnerability in analysis:
                        for line in analysis[vulnerability]['violations']:
                            if is_sentence_in_text(target_vulnerability, vulnerability):
                                res = True
                                lines.extend([line + 1])

            elif tool == 'slither':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['check'].strip()
                    line = None
                    if 'source_mapping' in result['elements'][0] and len(
                            result['elements'][0]['source_mapping']['lines']) > 0:
                        line = result['elements'][0]['source_mapping']['lines']
                    if is_sentence_in_text(target_vulnerability, vulnerability) and line is not None:
                        res = True
                        lines.extend(line)

            elif tool == 'smartcheck':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['name'].strip()
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        res = True
                        lines.extend([result['line']])

            elif tool == 'solhint':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['type'].strip()
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        res = True
                        lines.extend([int(result['line'])])

    return res, lines


# Tokens whose presence in a "safe" function marks it as a harder negative
# example (uses a sensitive operation but was not flagged as vulnerable).
SENSITIVE_OPERATORS_REETRANCY = ['call', 'delegatecall', 'send', 'transfer', 'selfdestruct']


def contains_sensitive_operator(function_body):
    """Check whether a function body contains any reentrancy-sensitive
    operator (call, delegatecall, send, transfer, selfdestruct)."""
    return any(operator in function_body for operator in SENSITIVE_OPERATORS_REETRANCY)


# =============================================================================
# Function extraction and tokenization
# =============================================================================

def extract_functions_with_bodies(contract_code):
    """
    Extract every function definition from a contract, tracking brace
    nesting to capture the full body, and the start/end source line
    numbers (used later to match against vulnerable-line data).

    :return: list of dicts: {function_body, start_line, end_line, label}
             (label defaults to 0 / safe and is set by
             label_functions_by_vulnerable_lines()).
    """
    functions = []
    function_pattern = re.compile(
        r'function\s+\w+\s*\(.*?\)\s*(public|private|internal|external)?\s*(view|pure)?\s*(returns\s*\(.*?\))?\s*{')

    lines = contract_code.splitlines()
    open_brackets = 0
    in_function = False
    function_body = []
    start_line = 0

    for i, line in enumerate(lines):
        if not in_function:
            match = function_pattern.search(line)
            if match:
                in_function = True
                start_line = i + 1
                function_body = [line]
                open_brackets = line.count('{') - line.count('}')
        else:
            function_body.append(line)
            open_brackets += line.count('{')
            open_brackets -= line.count('}')
            if open_brackets == 0:
                functions.append({
                    'function_body': '\n'.join(function_body),
                    'start_line': start_line,
                    'end_line': i + 1,
                    'label': 0
                })
                in_function = False

    return functions


def tokenize_solidity_code(code):
    """Tokenize a single preprocessed source line into Solidity keywords,
    operators/punctuation, and identifiers (including FUN<N>/VAR<N>
    placeholders produced by PreProcessTools)."""
    pattern = r'\b(?:function|returns|uint256|internal|constant|assert|return|require|if|else|for|while)\b|[=<>!*&|()+\-;/\}]|\b[a-zA-Z_][a-zA-Z0-9_]*\b'
    return re.findall(pattern, code)


def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    """Set label=1 for any function whose source range overlaps a
    reported vulnerable line."""
    for func in functions:
        if any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1


# =============================================================================
# Embedding (Word2Vec / FastText)
# =============================================================================

def vectorize_tokens(tokens, global_model=None):
    """
    Convert a function's tokens into a (sequence_length, vector_length)
    Word2Vec embedding matrix, used by the BiLSTM branch.

    Priority order:
      1. `global_model` passed explicitly by the caller.
      2. The saved global Word2Vec model at GLOBAL_WORD2VEC_PATH, if present.
      3. Fallback: a per-function Word2Vec model trained only on `tokens`.
         (kept for backward compatibility; produces noisier, function-local
         vectors since each model only sees ~20-200 tokens of context.)
    """
    if global_model is not None:
        embeddings = [
            global_model.wv[word] if word in global_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    elif os.path.exists(GLOBAL_WORD2VEC_PATH):
        loaded_model = Word2Vec.load(GLOBAL_WORD2VEC_PATH)
        embeddings = [
            loaded_model.wv[word] if word in loaded_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    else:
        word2vec_model = Word2Vec(sentences=[tokens], vector_size=vector_length, window=5, min_count=1, workers=4)
        embeddings = [
            word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(vector_length)
            for word in tokens
        ]

    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))
    return np.array(embeddings, dtype='float32')


def vectorize_tokens_fasttext(tokens, global_model=None):
    """
    Same as vectorize_tokens(), but using FastText embeddings. Used only
    to build the attention-map input for the U-Net branch.
    """
    if global_model is not None:
        embeddings = [
            global_model.wv[word] if word in global_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    elif os.path.exists(GLOBAL_FASTTEXT_PATH):
        loaded_model = FastText.load(GLOBAL_FASTTEXT_PATH)
        embeddings = [
            loaded_model.wv[word] if word in loaded_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    else:
        fasttext_model = FastText(
            sentences=[tokens], vector_size=vector_length, window=5,
            min_count=1, workers=4, sg=0, bucket=2000
        )
        embeddings = [
            fasttext_model.wv[word] if word in fasttext_model.wv else np.zeros(vector_length)
            for word in tokens
        ]

    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))
    return np.array(embeddings, dtype='float32')


def _collect_corpus_tokens(max_contracts):
    """Shared helper for the global-embedding builders below: gather one
    token list per function across a (optionally subsampled) set of
    contracts."""
    all_tokens_global = []
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]

    if len(files) > max_contracts:
        import random
        random.seed(42)
        files = random.sample(files, max_contracts)

    print(f"Building global embedding corpus from {len(files)} contracts...")
    for file_idx, file in enumerate(files):
        if file_idx % 1000 == 0:
            print(f"  Processed {file_idx}/{len(files)} contracts...")
        try:
            with open(file, encoding="utf8") as f:
                contract_content = f.read()
        except Exception:
            continue

        for func in extract_functions_with_bodies(contract_content):
            fragments = PreProcessTools.get_fragments(func['function_body'])
            func_tokens = []
            for fragment in fragments:
                if fragment.strip():
                    tokens = tokenize_solidity_code(fragment)
                    if tokens:
                        func_tokens.extend(tokens)
            if func_tokens:
                all_tokens_global.append(func_tokens)

    return all_tokens_global


def build_global_fasttext_model(max_contracts=15000):
    """
    Train a single FastText model over a corpus-wide sample of functions
    (instead of one model per function), saved to GLOBAL_FASTTEXT_PATH.

    Rationale: a per-function FastText model only sees that function's
    tokens, so the vector for a common token like "call" can differ wildly
    between functions. A shared, corpus-wide model gives every token a
    stable vector, which the U-Net branch needs to generalize patterns
    like "call.value" across different contracts.
    """
    all_tokens_global = _collect_corpus_tokens(max_contracts)
    print(f"Training global FastText on {len(all_tokens_global)} functions...")
    global_model = FastText(
        sentences=all_tokens_global, vector_size=vector_length, window=5,
        min_count=1, workers=4, sg=0, bucket=50000
    )
    global_model.save(GLOBAL_FASTTEXT_PATH)
    print(f"Global FastText saved to {GLOBAL_FASTTEXT_PATH} (vocabulary size: {len(global_model.wv)})")
    return global_model


def build_global_word2vec_model(max_contracts=15000):
    """Same as build_global_fasttext_model(), but trains a Word2Vec model
    for the BiLSTM branch, saved to GLOBAL_WORD2VEC_PATH."""
    all_tokens_global = _collect_corpus_tokens(max_contracts)
    print(f"Training global Word2Vec on {len(all_tokens_global)} functions...")
    global_model = Word2Vec(sentences=all_tokens_global, vector_size=vector_length, window=5, min_count=1, workers=4)
    global_model.save(GLOBAL_WORD2VEC_PATH)
    print(f"Global Word2Vec saved to {GLOBAL_WORD2VEC_PATH} (vocabulary size: {len(global_model.wv)})")
    return global_model


# =============================================================================
# Attention map (U-Net input) construction
# =============================================================================

def create_attention_map(embedding_matrix, real_token_count, window=co_occurrence_window):
    """
    Build a (sequence_length, sequence_length, 3) "image-like" input for
    the U-Net branch from a function's FastText embedding matrix.

    Three independent channels are used instead of collapsing everything
    into a single value, because cosine similarity ranges over [-1, +1]:
    any single-channel encoding (e.g. similarity * co-occurrence) maps at
    least two distinct situations - "tokens are not near each other" and
    "tokens are near each other but semantically opposite" - to the same
    output value, which is ambiguous for the network.

      Channel 1 (co-occurrence): 1 if the two tokens are within `window`
        positions of each other in the function, else 0. Unambiguous.
      Channel 2 (similarity): cosine similarity between the two tokens'
        embedding vectors, rescaled from [-1, 1] to [0, 1]. Kept even for
        tokens that are far apart, so semantic relationships across the
        whole function are not discarded.
      Channel 3 (interaction): channel_2 * channel_1 - the same "semantic
        similarity AND nearby" signal used in the original single-channel
        design, kept as an additional, redundant-but-helpful feature.

    :param embedding_matrix: (sequence_length, vector_length) FastText matrix
    :param real_token_count: number of real (non-padding) tokens
    :param window: co-occurrence window size, in tokens
    :return: (sequence_length, sequence_length, 3) float32 array
    """
    norms = np.linalg.norm(embedding_matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1e-10  # avoid division by zero for padding vectors
    normalized = embedding_matrix / norms
    similarity_matrix = np.dot(normalized, normalized.T)  # range [-1, 1]

    seq_len = embedding_matrix.shape[0]
    co_matrix = np.zeros((seq_len, seq_len), dtype='float32')
    limit = min(real_token_count, seq_len)
    for idx in range(limit):
        for w in range(1, window + 1):
            if idx + w < limit:
                co_matrix[idx][idx + w] = 1.0
                co_matrix[idx + w][idx] = 1.0

    channel_cooccurrence = co_matrix
    channel_similarity = (similarity_matrix + 1) / 2
    channel_interaction = channel_similarity * co_matrix

    attention_map = np.stack([channel_cooccurrence, channel_similarity, channel_interaction], axis=-1)
    return attention_map.astype('float32')


# =============================================================================
# Dataset construction
# =============================================================================

def load_batches_by_prefix(folder, prefix, file_extension=".pkl"):
    """
    Load and concatenate every pickle file in `folder` whose name starts
    with `prefix` (e.g. "emb_" or "att_"). Filenames are sorted before
    loading so that, for a given batch/category, the "emb_" and "att_"
    files are concatenated in the same relative order - this is required
    for X_emb[i] and X_att[i] to refer to the same underlying function.
    """
    X_batches, Y_batches = [], []
    matched_files = sorted([
        f for f in os.listdir(folder)
        if f.endswith(file_extension) and f.startswith(prefix)
    ])
    for file in matched_files:
        with open(os.path.join(folder, file), 'rb') as f:
            X, Y = pickle.load(f)
            X_batches.append(X)
            Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)


def process_batch_with_categorization_for_unet(files, target_vulnerability, batch_size, batch_index,
                                                global_fasttext_model=None, global_word2vec_model=None):
    """
    Build both data representations (embedding + attention map) for every
    function in `files`, and save them under CACHE_DIR_UNET.

    Functions are split into three categories:
      - vulnerable       (label == 1)
      - sensitive_negative (label == 0, but contains a reentrancy-sensitive
                             operator - a harder negative example)
      - safe              (label == 0, no sensitive operator)

    Each category is saved as two files per batch: "emb_<category>_batch_<i>.pkl"
    and "att_<category>_batch_<i>.pkl", with matching sample order/labels.
    """
    X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative = [], [], []
    X_vulnerable_emb, X_vulnerable_att, Y_vulnerable = [], [], []
    X_safe_emb, X_safe_att, Y_safe = [], [], []

    max_function_length = 100  # must match sequence_length

    sc_files = [f for f in files if f.endswith(".sol")]
    print(f"Processing {len(sc_files)} contracts...")
    for file in sc_files:
        with open(file, encoding="utf8") as f:
            contract_content = f.read()

        functions = extract_functions_with_bodies(contract_content)
        name = Path(file).stem
        res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)
        label_functions_by_vulnerable_lines(functions, vulnerable_lines)

        for func in functions:
            fragments = PreProcessTools.get_fragments(func['function_body'])
            label = func['label']

            # Collect every token across all lines of the function (not
            # per-fragment) so the embedding model sees the full function
            # as context.
            all_tokens = []
            for fragment in fragments:
                if fragment.strip():
                    tokens = tokenize_solidity_code(fragment)
                    if tokens:
                        all_tokens.extend(tokens)

            if not all_tokens:
                continue

            # BiLSTM branch input (Word2Vec)
            func_vectors = vectorize_tokens(all_tokens, global_model=global_word2vec_model)
            padded_function = pad_sequences(
                [func_vectors], maxlen=max_function_length, padding='post', dtype='float32'
            )[0]

            # U-Net branch input (FastText -> attention map)
            func_vectors_fasttext = vectorize_tokens_fasttext(all_tokens, global_model=global_fasttext_model)
            padded_function_fasttext = pad_sequences(
                [func_vectors_fasttext], maxlen=max_function_length, padding='post', dtype='float32'
            )[0]
            real_token_count = min(len(all_tokens), sequence_length)
            att_map = create_attention_map(padded_function_fasttext, real_token_count)

            if label == 1:
                X_vulnerable_emb.append(padded_function)
                X_vulnerable_att.append(att_map)
                Y_vulnerable.append(label)
            elif contains_sensitive_operator(func['function_body']):
                X_sensitive_negative_emb.append(padded_function)
                X_sensitive_negative_att.append(att_map)
                Y_sensitive_negative.append(label)
            else:
                X_safe_emb.append(padded_function)
                X_safe_att.append(att_map)
                Y_safe.append(label)

    def _to_arrays(x_emb, x_att, y):
        return (
            np.array(x_emb, dtype='float32'),
            np.array(x_att, dtype='float32'),
            np.array(y, dtype='int32')
        )

    X_vulnerable_emb, X_vulnerable_att, Y_vulnerable = _to_arrays(X_vulnerable_emb, X_vulnerable_att, Y_vulnerable)
    X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative = _to_arrays(
        X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative)
    X_safe_emb, X_safe_att, Y_safe = _to_arrays(X_safe_emb, X_safe_att, Y_safe)

    os.makedirs(CACHE_DIR_UNET, exist_ok=True)

    with open(os.path.join(CACHE_DIR_UNET, f"emb_vulnerable_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_vulnerable_emb, Y_vulnerable), f)
    with open(os.path.join(CACHE_DIR_UNET, f"emb_sensitive_negative_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_sensitive_negative_emb, Y_sensitive_negative), f)
    with open(os.path.join(CACHE_DIR_UNET, f"emb_safe_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_safe_emb, Y_safe), f)

    with open(os.path.join(CACHE_DIR_UNET, f"att_vulnerable_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_vulnerable_att, Y_vulnerable), f)
    with open(os.path.join(CACHE_DIR_UNET, f"att_sensitive_negative_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_sensitive_negative_att, Y_sensitive_negative), f)
    with open(os.path.join(CACHE_DIR_UNET, f"att_safe_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_safe_att, Y_safe), f)

    print(f"Batch {batch_index} saved to {CACHE_DIR_UNET} (emb_/att_ files)")


# =============================================================================
# Model branches
# =============================================================================

def build_unet_branch(input_shape):
    """
    U-Net-style encoder/decoder branch consuming the attention-map input.

    Design notes from experimentation:
      - BatchNormalization was tried and removed: on this sparse,
        attention-map input it caused train/inference statistic mismatch
        and validation accuracy collapsed (86.73% -> 64.32%). Dropout-based
        regularization only is used instead.
      - SpatialDropout2D (not plain Dropout) is used on the convolutional
        bottleneck, since neighboring pixels in a feature map are highly
        correlated and plain per-pixel Dropout is easily "guessed around"
        by the network; SpatialDropout2D drops whole feature channels.
      - Both GlobalAveragePooling2D and GlobalMaxPooling2D are used and
        concatenated: functions shorter than sequence_length leave a large
        padded (zero) region in the map, which dilutes a pure average; max
        pooling is less sensitive to padding and preserves strong local
        patterns.
    """
    inputs = Input(shape=input_shape, name='attention_map_input')

    # Encoder
    conv1 = Conv2D(64, (3, 3), activation='relu', padding='same')(inputs)
    pool1 = MaxPooling2D((2, 2))(conv1)

    conv2 = Conv2D(128, (3, 3), activation='relu', padding='same')(pool1)
    pool2 = MaxPooling2D((2, 2))(conv2)

    # Bottleneck
    conv3 = Conv2D(256, (3, 3), activation='relu', padding='same')(pool2)
    conv3 = SpatialDropout2D(0.3)(conv3)

    # Decoder (with skip connections)
    up1 = UpSampling2D((2, 2))(conv3)
    concat1 = concatenate([conv2, up1])
    conv4 = Conv2D(128, (3, 3), activation='relu', padding='same')(concat1)

    up2 = UpSampling2D((2, 2))(conv4)
    concat2 = concatenate([conv1, up2])
    conv5 = Conv2D(64, (3, 3), activation='relu', padding='same')(concat2)

    avg_pool = GlobalAveragePooling2D()(conv5)
    max_pool = GlobalMaxPooling2D()(conv5)
    pooled = concatenate([avg_pool, max_pool])

    dense_out = Dense(128, activation='relu')(pooled)
    return inputs, dense_out


def build_bilstm_branch(input_shape):
    """BiLSTM branch consuming the (sequence_length, vector_length)
    Word2Vec embedding matrix."""
    inputs = Input(shape=input_shape, name='embedding_input')
    x = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    x = Dropout(0.5)(x)
    x = Bidirectional(LSTM(64))(x)
    return inputs, x


def build_unet_bilstm_model(seq_len=sequence_length, vec_len=vector_length):
    """
    Joint (end-to-end) combination of the U-Net and BiLSTM branches:
    both branches' feature vectors are concatenated and fed through a
    small classification head, with both branches trained together from
    scratch. Kept for reference/comparison - see train_UNET_LSTM().
    """
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 3))
    lstm_input, lstm_output = build_bilstm_branch((seq_len, vec_len))

    combined = concatenate([unet_output, lstm_output])
    dense1 = Dense(128, activation='relu')(combined)
    dense2 = Dense(64, activation='relu')(dense1)
    outputs = Dense(1, activation='sigmoid')(dense2)

    return Model(inputs=[unet_input, lstm_input], outputs=outputs)


def build_unet_only_model(seq_len=sequence_length):
    """U-Net branch with its own classification head, for standalone
    training/evaluation (test_unet_branch_alone())."""
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 3))
    x = Dropout(0.3)(unet_output)
    dense1 = Dense(64, activation='relu', kernel_regularizer='l2')(x)
    outputs = Dense(1, activation='sigmoid')(dense1)
    return Model(inputs=unet_input, outputs=outputs)


def build_stacking_meta_model():
    """
    Small meta-model for the stacking ensemble: takes the two base
    models' output probabilities [p_lstm, p_unet] and learns a combined
    decision. Unlike build_unet_bilstm_model() above, the base models here
    are trained fully independently and frozen - only their final
    probabilities are combined, avoiding any gradient interference
    between the two branches.
    """
    meta_input = Input(shape=(2,), name='meta_input')
    x = Dense(8, activation='relu')(meta_input)
    output = Dense(1, activation='sigmoid')(x)
    return Model(inputs=meta_input, outputs=output)


# =============================================================================
# Training entry points
# =============================================================================

def train_UNET_LSTM():
    """Train the joint U-Net+BiLSTM model (build_unet_bilstm_model) end-to-end."""
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")

    print(f"Shape of X_att (attention map): {X_att.shape}")
    print(f"Shape of X_emb (embedding): {X_emb.shape}")
    print(f"Shape of Y: {Y_att.shape}")
    assert np.array_equal(Y_att, Y_emb), "Y order mismatch between att_ and emb_ files - check the cache files"
    print("Distribution in Y:", np.unique(Y_att, return_counts=True))

    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)
    X_att_train, X_att_test = X_att[train_idx], X_att[test_idx]
    X_emb_train, X_emb_test = X_emb[train_idx], X_emb[test_idx]
    Y_train, Y_test = Y_att[train_idx], Y_att[test_idx]
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    model = build_unet_bilstm_model()
    model.compile(optimizer=Adam(learning_rate=0.001), loss=focal_loss(alpha=0.25, gamma=2.0), metrics=['accuracy'])
    model.summary()

    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
    history = model.fit(
        [X_att_train, X_emb_train], Y_train,
        epochs=50, batch_size=64, validation_split=0.2,
        callbacks=[early_stopping], verbose=2
    )

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('U-Net(AttentionMap) + BiLSTM - Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()
    output_image_path = os.path.join(ROOT, 'output', 'training_plot_unet_attention_lstm.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (model.predict([X_att_test, X_emb_test]) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)
    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1]))

    model.save(os.path.join(ROOT, 'output', 'final_unet_attention_lstm_model.keras'))
    print("Training complete with U-Net(AttentionMap) + BiLSTM.")


def train_LSTM():
    """Train the BiLSTM branch alone on the embedding ("emb_") dataset."""
    X, Y = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    model = Sequential([
        Input(shape=(X_train.shape[1], X_train.shape[2])),
        Bidirectional(LSTM(128, return_sequences=True)),
        Dropout(0.5),
        Bidirectional(LSTM(64)),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer=Adam(learning_rate=0.001), loss=focal_loss(alpha=0.25, gamma=2.0), metrics=['accuracy'])

    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
    history = model.fit(
        X_train, Y_train,
        epochs=50, batch_size=128, validation_split=0.2,
        callbacks=[early_stopping], verbose=2
    )

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('Model Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()
    output_image_path = os.path.join(ROOT, 'output', 'training_plot_lstm.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (model.predict(X_test) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)
    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1]))

    model.save(os.path.join(ROOT, 'output', 'final_LSTM_model.keras'))
    print("Training complete with LSTM.")


def test_unet_branch_alone():
    """Train and evaluate the U-Net branch alone on the attention-map
    ("att_") dataset. Saves the trained model for later use in
    check_ensemble_potential() and train_stacking_ensemble()."""
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    print(f"Shape of X_att: {X_att.shape}")
    print("Distribution in Y:", np.unique(Y_att, return_counts=True))

    X_train, X_test, Y_train, Y_test = train_test_split(X_att, Y_att, test_size=0.2, random_state=42)

    majority_baseline = max(np.mean(Y_test == 0), np.mean(Y_test == 1))
    print(f"Majority-class baseline accuracy: {majority_baseline:.4f}")

    model = build_unet_only_model()
    model.compile(optimizer=Adam(learning_rate=0.001), loss=focal_loss(alpha=0.25, gamma=2.0), metrics=['accuracy'])
    model.summary()

    early_stopping = EarlyStopping(monitor='val_accuracy', mode='max', patience=10, restore_best_weights=True)
    reduce_lr = ReduceLROnPlateau(monitor='val_accuracy', mode='max', factor=0.5, patience=4, min_lr=1e-6, verbose=1)

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    checkpoint = ModelCheckpoint(
        os.path.join(ROOT, 'output', 'best_unet_only_model.keras'),
        monitor='val_accuracy', mode='max', save_best_only=True
    )

    history = model.fit(
        X_train, Y_train,
        epochs=50, batch_size=128, validation_split=0.2,
        callbacks=[early_stopping, reduce_lr, checkpoint], verbose=2
    )

    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('U-Net Only (Attention Map) - Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()
    output_image_path = os.path.join(ROOT, 'output', 'training_plot_unet_only.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (model.predict(X_test) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)

    print(f"\n{'=' * 50}")
    print(f"U-Net-only accuracy:       {accuracy:.4f}")
    print(f"Majority-class baseline:   {majority_baseline:.4f}")
    print(f"Improvement over baseline: {(accuracy - majority_baseline) * 100:.2f}%")
    print(f"{'=' * 50}\n")
    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1]))

    model.save(os.path.join(ROOT, 'output', 'final_unet_only_model.keras'))
    print(f"Model saved to {os.path.join(ROOT, 'output', 'final_unet_only_model.keras')}")


def check_ensemble_potential():
    """
    Compare the two independently-trained models' predictions on the same
    test split to see how correlated their errors are - i.e. how much
    headroom a combination could realistically gain. Requires
    final_LSTM_model.keras and final_unet_only_model.keras to already
    exist (train_LSTM() and test_unet_branch_alone() must have been run).
    """
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")
    assert np.array_equal(Y_att, Y_emb), "Y order mismatch between att_ and emb_ files - check the cache files"

    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)
    X_att_test, X_emb_test = X_att[test_idx], X_emb[test_idx]
    Y_test = Y_att[test_idx]

    lstm_model = load_model(
        os.path.join(ROOT, 'output', 'final_LSTM_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )
    unet_model = load_model(
        os.path.join(ROOT, 'output', 'final_unet_only_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )

    pred_lstm = (lstm_model.predict(X_emb_test).flatten() > 0.5).astype(int)
    pred_unet = (unet_model.predict(X_att_test).flatten() > 0.5).astype(int)

    lstm_correct = (pred_lstm == Y_test)
    unet_correct = (pred_unet == Y_test)

    only_lstm_right = np.mean(lstm_correct & ~unet_correct)
    only_unet_right = np.mean(~lstm_correct & unet_correct)
    both_right = np.mean(lstm_correct & unet_correct)
    both_wrong = np.mean(~lstm_correct & ~unet_correct)

    print(f"Only LSTM correct:  {only_lstm_right * 100:.2f}%")
    print(f"Only U-Net correct: {only_unet_right * 100:.2f}%")
    print(f"Both correct:       {both_right * 100:.2f}%")
    print(f"Both wrong:         {both_wrong * 100:.2f}%")
    print(f"\nTheoretical ensemble improvement ceiling: {(only_lstm_right + only_unet_right) * 100:.2f}%")


def train_stacking_ensemble():
    """
    Train a stacking ensemble meta-model on top of pre-trained LSTM and U-Net models.

    This function loads the pre-trained LSTM and U-Net models, extracts their output
    probabilities (not class predictions), and trains a small meta-model (2 inputs,
    8 neurons, 1 output) to learn how to combine them optimally.

    Requirements:
        - final_LSTM_model.keras must exist in ROOT/output/
        - final_unet_only_model.keras must exist in ROOT/output/
        - Both models must have been trained with the same data split (random_state=42)
    """

    # =========================================================================
    # LOAD DATA
    # =========================================================================
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")
    assert np.array_equal(Y_att, Y_emb), "Y order mismatch between att and emb files"

    # Split data with fixed random seed for reproducibility
    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)

    X_att_train, X_att_test = X_att[train_idx], X_att[test_idx]
    X_emb_train, X_emb_test = X_emb[train_idx], X_emb[test_idx]
    Y_train, Y_test = Y_att[train_idx], Y_att[test_idx]

    # =========================================================================
    # LOAD PRE-TRAINED BASE MODELS
    # =========================================================================
    # Custom loss required for loading models trained with focal_loss
    lstm_model = load_model(
        os.path.join(ROOT, 'output', 'final_LSTM_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )
    unet_model = load_model(
        os.path.join(ROOT, 'output', 'final_unet_only_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )

    # =========================================================================
    # EXTRACT META-FEATURES: output probabilities from both base models
    # =========================================================================
    print("Generating meta-features from base models on training data...")
    p_lstm_train = lstm_model.predict(X_emb_train, verbose=0).flatten()
    p_unet_train = unet_model.predict(X_att_train, verbose=0).flatten()
    meta_X_train = np.column_stack([p_lstm_train, p_unet_train])

    print("Generating meta-features from base models on test data...")
    p_lstm_test = lstm_model.predict(X_emb_test, verbose=0).flatten()
    p_unet_test = unet_model.predict(X_att_test, verbose=0).flatten()
    meta_X_test = np.column_stack([p_lstm_test, p_unet_test])

    # =========================================================================
    # BUILD META-MODEL
    # =========================================================================
    # Simple architecture: 2 inputs → Dense(8) → Dense(1) with sigmoid
    meta_model = build_stacking_meta_model()
    meta_model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),
        metrics=['accuracy']
    )

    # =========================================================================
    # TRAIN META-MODEL
    # =========================================================================
    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    # Store history for plotting
    history = meta_model.fit(
        meta_X_train, Y_train,
        epochs=50,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    # =========================================================================
    # SAVE TRAINING PLOT
    # =========================================================================
    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('Stacking Ensemble - Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()

    output_image_path = os.path.join(ROOT, 'output', 'training_plot_stacking_ensemble.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    # =========================================================================
    # EVALUATE ON TEST DATA
    # =========================================================================
    Y_pred = (meta_model.predict(meta_X_test, verbose=0) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)

    print(f"\n{'=' * 50}")
    print(f"Stacking Ensemble Accuracy: {accuracy:.4f}")
    print(f"{'=' * 50}\n")
    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1]))

    # =========================================================================
    # SAVE FINAL META-MODEL
    # =========================================================================
    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    meta_model.save(os.path.join(ROOT, 'output', 'final_stacking_ensemble.keras'))
    print(f"Model saved to {os.path.join(ROOT, 'output', 'final_stacking_ensemble.keras')}")


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    # --- Step 1: dataset construction (run once) ---
    # Builds both the "emb_" and "att_" datasets for every contract batch.
    # Optionally pass global_fasttext_model / global_word2vec_model (built
    # once via build_global_fasttext_model() / build_global_word2vec_model())
    # to use corpus-wide embeddings instead of per-function ones.
    #
    # files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    # global_ft_model = (
    #     FastText.load(GLOBAL_FASTTEXT_PATH) if os.path.exists(GLOBAL_FASTTEXT_PATH)
    #     else build_global_fasttext_model()
    # )
    # global_w2v_model = (
    #     Word2Vec.load(GLOBAL_WORD2VEC_PATH) if os.path.exists(GLOBAL_WORD2VEC_PATH)
    #     else build_global_word2vec_model()
    # )
    # for batch_index, i in enumerate(range(0, len(files), batch_size)):
    #     batch_files = files[i:i + batch_size]
    #     process_batch_with_categorization_for_unet(
    #         batch_files, target_vulner, batch_size, batch_index,
    #         global_fasttext_model=global_ft_model,
    #         global_word2vec_model=global_w2v_model
    #     )

    # --- Step 2: training (run one at a time) ---
    # train_LSTM()
    # train_UNET_LSTM()
    # test_unet_branch_alone()
    # check_ensemble_potential()
    train_stacking_ensemble()
