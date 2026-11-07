# Reentrancy Vulnerability Detection in Smart Contracts with a Hybrid BiLSTM–U-Net Model

M.Sc. thesis project — Islamic Azad University, Science and Research Branch
(Faculty of Sciences and Research, Department of Computer and Information Technology; Information Technology Engineering, E-Commerce).

**Thesis title:** *A Method for Smart Contract Vulnerability Detection on Blockchain Using a Hybrid LSTM–U-Net Deep Learning Model*
**Author:** Sajjad Shahbazi
**Supervisor:** Dr. Mahyar Sadri Shojaei  **Advisor:** Dr. Azadeh Zamanifar

The latest version of the code is in [`scripts85_colab_lstm`](scripts85_colab_lstm).

---

## Abstract

Blockchain-based smart contracts, due to their immutability after deployment, have turned security vulnerabilities such as Reentrancy into costly threats. Existing vulnerability-detection methods mostly rely on fixed rules defined by experts, whose efficiency and scalability decline as contract complexity increases.

This research proposes a hybrid method for detecting Reentrancy vulnerabilities in Solidity smart contracts that leverages two complementary sources of information simultaneously: a BiLSTM branch operating on the Word2Vec token-embedding sequence of the code, and a U-Net branch operating on a novel image-like representation called the **Attention Map**. This representation is built from a token co-occurrence matrix (sequential information) and a semantic similarity matrix (semantic information), enabling the convolutional network to detect dangerous code patterns in two dimensions.

Unlike joint training of the two branches, which showed no improvement due to gradient interference and overfitting, the two models were trained independently and their probability outputs were combined using a **Stacking Ensemble** approach. Evaluation on the SmartBugs Wild dataset (47,398 smart contracts) showed that the proposed model achieved **88.85% accuracy**, compared to 85.80% for the CBGRU baseline model. The results show that combining structural and semantic information through the Stacking approach yields more stable and accurate performance than joint training of the two branches.

**Keywords:** Smart Contract, Blockchain, Deep Learning, BiLSTM, U-Net, Attention Map, Stacking Ensemble

---

## What was done

1. **Data and labels.** The SmartBugs Wild dataset (Solidity source files of real Ethereum contracts) is used. Vulnerability labels come from the output of the analysis tools stored under `results/` (HoneyBadger, Maian, Manticore, Mythril, Osiris, Oyente, Securify, Slither, SmartCheck). The target vulnerability in this work is **Reentrancy**.
2. **Preprocessing** (`PreProcessTools.py`). The `pragma` line, comments, non-ASCII characters and leading whitespace are removed while keeping line numbers unchanged, so that vulnerable lines reported by the tools still match. User-defined function and variable names are replaced by `FUN<N>` / `VAR<N>`.
3. **Function extraction and labeling.** Each function is extracted with its start and end line. A function is labeled *vulnerable* if a tool reported a Reentrancy finding inside its line range.
4. **Class balancing.** Functions are split into three groups: *vulnerable*, *safe*, and *sensitive negative* (not vulnerable, but using a sensitive operator such as `call`, `delegatecall`, `send`, `transfer`, `selfdestruct`). The sensitive negatives are kept on purpose, so the network cannot learn the shortcut "contains `call.value` ⇒ vulnerable". Focal Loss (α = 0.25, γ = 2) additionally handles the remaining imbalance.
5. **Tokenization and embeddings.** All tokens of a function are collected into one sequence (100 tokens, zero-padded or truncated) and embedded into 300 dimensions with corpus-wide (*global*) models: Word2Vec for the BiLSTM branch and FastText for the Attention Map. A global model gives a token such as `call` the same vector in every function, which lets the network generalize patterns like `call.value` across contracts.
6. **Attention Map.** For every function a `100 × 100 × 3` image-like tensor is built from the FastText vectors:
   - channel 1 — co-occurrence (1 if two tokens are at most 3 positions apart, else 0),
   - channel 2 — cosine similarity of the two token vectors, rescaled to [0, 1],
   - channel 3 — interaction (channel 1 × channel 2).

   Three channels are used because a single product channel maps "tokens are far apart" and "tokens are close but semantically opposite" to the same value (0).
7. **Models.**
   - *BiLSTM branch* — BiLSTM(128) → Dropout(0.5) → BiLSTM(64) → sigmoid; input `100 × 300`.
   - *U-Net branch* — convolutional encoder/decoder with skip connections, SpatialDropout2D, global average + max pooling, dense head; input `100 × 100 × 3`.
   - *Concatenate (joint training)* — both branches trained together end to end; kept for comparison.
   - *Stacking Ensemble (final model)* — both branches trained independently, then a small meta-model (2 → 8 → 1, 65 parameters) is trained on their output probabilities.
8. **Training setup.** Adam (lr = 0.001), up to 50 epochs, batch size 128, Focal Loss, Early Stopping (patience 10), ReduceLROnPlateau for the U-Net (factor 0.5, patience 4, min lr 1e-6). 80/20 train/test split with `random_state=42`, identical for all models. Training ran on Google Colab with an NVIDIA Tesla T4 GPU and High-RAM runtime; the data preparation ran on a local machine because the preprocessed data is very large (about 150 GB).

---

## Results

Test set: 9,524 samples. Majority-class baseline accuracy: 59.67% (28,520 safe / 19,099 vulnerable samples in total).

| Model | Accuracy | Precision (Vuln.) | Recall (Vuln.) | F1 (Vuln.) |
| --- | --- | --- | --- | --- |
| BiLSTM only | 87.33% | 0.87 | 0.80 | 0.84 |
| U-Net only (Attention Map) | 88.52% | 0.86 | 0.86 | 0.86 |
| Concatenate (joint training) | 87.59% | 0.85 | 0.84 | 0.85 |
| **Stacking Ensemble** | **88.85%** | 0.86 | 0.87 | 0.86 |

For reference, the CBGRU baseline reaches 85.80% accuracy on the same dataset, and its BiLSTM-only model 74.60%.

Training curves:

| BiLSTM only | U-Net only |
| --- | --- |
| ![BiLSTM](scripts85_colab_lstm/training_plot_lstm.png) | ![U-Net](scripts85_colab_lstm/training_plot_unet_only.png) |

| Concatenate | Stacking Ensemble |
| --- | --- |
| ![Concatenate](scripts85_colab_lstm/training_plot_unet_attention_lstm.png) | ![Stacking](scripts85_colab_lstm/training_plot_stacking_ensemble.png) |

---

## Repository layout

| Path | Content |
| --- | --- |
| `contracts/` | Solidity source files (`.sol`) of the SmartBugs Wild dataset |
| `results/` | Output of the analysis tools, used to label vulnerable lines |
| `scripts85_colab_lstm/` | **Final code** (`PrepareDataSet.py`, `PreProcessTools.py`) and output figures |
| `scripts*/` | Earlier experiment iterations (kept for history) |
| `requirements.txt` | Python packages (full `pip freeze` of the local Windows environment) |

`PrepareDataSet.py` — dataset construction (labels, tokens, embeddings, Attention Maps), model definitions and all training entry points.
`PreProcessTools.py` — source-code cleaning and identifier normalization.

---

## How to run

### 1. Requirements

- Python 3.10+ and TensorFlow/Keras 2.16 (`keras 3.x`, `.keras` model format), `gensim`, `scikit-learn`, `numpy`, `matplotlib`.
- Training: a GPU runtime is strongly recommended (the thesis used Colab, Tesla T4, High-RAM). The stacking step loads the whole dataset into memory (several GB).
- Dataset construction needs a lot of disk space (about 150 GB of cached `.pkl` files), so it was run locally and not on Colab.

On Colab:

```python
!git clone https://github.com/sajjadshahbazi/smartbugs-wild-with-content-and-result.git /content/smartbugs-wild-with-content-and-result
%cd /content/smartbugs-wild-with-content-and-result/scripts85_colab_lstm
!pip install gensim scikit-learn matplotlib
```

`requirements.txt` is a complete `pip freeze` from a local Windows machine (it contains `tensorflow-intel`), so on Colab or Linux install the packages above instead and keep the Colab TensorFlow.

### 2. Configure the paths

At the top of `PrepareDataSet.py` set `ROOT` to the folder that contains `contracts/` and `results/`:

```python
ROOT = '/content/smartbugs-wild-with-content-and-result'   # Colab / Linux (default)
```

Derived paths: cache folder `ROOT/vectorcollections_img`, trained models and figures in `ROOT/output`, global embedding models `ROOT/global_word2vec_model.bin` and `ROOT/global_fasttext_model.bin`.

> The module changes the working directory to `ROOT/contracts` when it is imported, so that folder must exist (even if it is empty when you only train from an existing cache).

### 3. Build the dataset (run once, local machine)

This creates the `emb_*.pkl` (BiLSTM input) and `att_*.pkl` (U-Net input) batches. Labels are read from `ROOT/results/<tool>/icse20/<contract>/result.json`.

```python
import os
import PrepareDataSet as p
from gensim.models import FastText, Word2Vec

files = [os.path.join(p.PATH, f) for f in os.listdir(p.PATH) if f.endswith('.sol')]

ft  = FastText.load(p.GLOBAL_FASTTEXT_PATH) if os.path.exists(p.GLOBAL_FASTTEXT_PATH) else p.build_global_fasttext_model()
w2v = Word2Vec.load(p.GLOBAL_WORD2VEC_PATH) if os.path.exists(p.GLOBAL_WORD2VEC_PATH) else p.build_global_word2vec_model()

for batch_index, i in enumerate(range(0, len(files), p.batch_size)):
    p.process_batch_with_categorization_for_unet(
        files[i:i + p.batch_size], p.target_vulner, p.batch_size, batch_index,
        global_fasttext_model=ft, global_word2vec_model=w2v)
```

The same code is available, commented out, in the `if __name__ == "__main__":` block of `PrepareDataSet.py`.

Each batch is saved as `emb_<category>_batch_<i>.pkl` and `att_<category>_batch_<i>.pkl` with the categories `vulnerable`, `sensitive_negative` and `safe`. The generated data is not stored in this repository because of its size. After the dataset is balanced, it is uploaded to Google Drive and mounted in Colab for training:

```python
from google.colab import drive
drive.mount('/content/drive')
# then point ROOT in PrepareDataSet.py to the folder on Drive (or copy vectorcollections_img to /content/...)
```

### 4. Train and evaluate (Colab, GPU)

Run the steps in this order (each can also be started from the `__main__` block of `PrepareDataSet.py`):

```python
import PrepareDataSet as p

p.train_LSTM()               # 1. BiLSTM branch      -> output/final_LSTM_model.keras
p.test_unet_branch_alone()   # 2. U-Net branch       -> output/final_unet_only_model.keras
p.check_ensemble_potential() # 3. (optional) how much do the two models' errors overlap?
p.train_stacking_ensemble()  # 4. final model        -> output/final_stacking_ensemble.keras
p.train_UNET_LSTM()          # (optional) joint/concatenate model, for comparison only
```

`train_stacking_ensemble()` needs the models from steps 1 and 2, and relies on the same fixed split (`random_state=42`) used by those steps. Every training function prints the classification report (accuracy, precision, recall, F1 per class) and saves its training curve as a `.png` in `ROOT/output`.

---

## Limitations

- Only the **Reentrancy** vulnerability is covered.
- The train/test split is made at the **function level**, not at the contract level, so functions of the same contract can appear in both sets.
- The preprocessed data (especially the Attention Maps) is very large (about 140–150 GB) and needs suitable infrastructure.
- The ensemble is hard to interpret: it is difficult to tell whether sequential or structural features drove a specific decision.
- Comparisons with other published models are only directly valid when they use the same dataset and vulnerability type (CBGRU does).

## Acknowledgements and data source

The contracts and tool outputs come from the **SmartBugs Wild** dataset (Durieux et al., 2020). The preprocessing idea and the baseline for comparison follow the CBGRU approach (Zhang et al., 2022).

## Citation

> Shahbazi, S. *A Method for Smart Contract Vulnerability Detection on Blockchain Using a Hybrid LSTM–U-Net Deep Learning Model.* M.Sc. thesis, Islamic Azad University, Science and Research Branch, 2026.
