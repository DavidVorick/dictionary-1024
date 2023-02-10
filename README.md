# dictionary-1024

dictionary-1024 is a mnemonic dictionary that can be used with cryptographic
seeds or to transform other binary data. The dictionary has 1024 words in it,
which means you can pack exactly 10 bits of entropy into each word. The
dictionary has the property that every word can be uniquely determined by its
first 3 characters. The API is designed such that only the first 3 characters
of a word are considered when doing a lookup in the dictionary.
