from gensim.models import Word2Vec

# Load your Word2Vec model
# Replace 'path_to_word2vec_model' with the path to your Word2Vec model
# model = Word2Vec.load("path_to_word2vec_model")

# Define a list of words to combine
words_to_combine = ["public", "library"]

# Combine the words
model = Word2Vec(str(words_to_combine), vector_size=100, window=5, min_count=1, sg=0)
embeddings = model.wv

model.build_vocab(["public"], update=True)

# Train the model with the updated vocabulary
# You may want to train with more epochs or adjust other parameters
model.train("public", total_examples=model.corpus_count, epochs=10)

# Save the updated model
model.save("updated_word2vec_model")

# Check if the combined word is in the model
for combined_word in words_to_combine:
    # If the combined word exists in the model, you can get its vector
    vector = model.wv[combined_word]
    print(f"Vector for '{combined_word}': {vector}")
else:
    print(f"Vector for '{combined_word}' not found in the model.")
