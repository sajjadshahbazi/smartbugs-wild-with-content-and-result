import os

import pandas

from script.vectorize_fragment import FragmentVectorizer

output_name = 'icse20'
duration_stat = {}

count = {}
output = {}

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
path = f"{ROOT}\\contract\\" # temp data set

def parse_file(file):
    # with open(filename, "r", encoding="utf8") as file:
        fragment = []
        fragment_val = 0
        print(file)
        for line in file:
            stripped = line.strip()
            if not stripped:
                continue
            if "-" * 33 in line and fragment:
                yield fragment, fragment_val
                fragment = []
            elif stripped.split()[0].isdigit():
                if fragment:
                    if stripped.isdigit():
                        fragment_val = int(stripped)
                    else:
                        fragment.append(stripped)
            else:
                fragment.append(stripped)


def get_vectors_df(file, vector_length=300):
    fragments = []
    count = 0
    vectorizer = FragmentVectorizer(vector_length)
    for fragment, val in parse_file(file):
        count += 1
        print("Collecting fragments...", count, end="\r")
        vectorizer.add_fragment(fragment)
        row = {"fragment": fragment, "val": val}
        fragments.append(row)
    print('Found {} forward slices and {} backward slices'
          .format(vectorizer.forward_slices, vectorizer.backward_slices))
    print()
    print("Training model...", end="\r")
    # vectorizer.train_model()
    # print()
    # vectors = []
    # count = 0
    print(fragments)
    # for fragment in fragments:
    #     count += 1
    #     print("Processing fragments...", count, end="\r")
    #     vector = vectorizer.vectorize(fragment["fragment"])
    #     row = {"vector": vector, "val": fragment["val"]}
    #     vectors.append(row)
    # print()
    # df = pandas.DataFrame(vectors)
    # return df


os.chdir(path)

for sss in ["1"]:
    for file in os.listdir():
        # Check whether file is in text format or not
        if file.endswith(".sol"):
            file_path = f"{path}\{file}"
            name = file.replace(".sol","")
            with open(file_path, "r", encoding="utf8") as fileCon:
            # with open(file_path, encoding="utf8") as fileCon:
                smartContractContent = fileCon.read()
                # print(smartContractContent)
                get_vectors_df(fileCon)
            # # call read text file function
            # if(read_text_file(file_path, name)):
            #     vul_count += 1
            # else :
            #     safe_count += 1

# print(f"sum safe smart contract: {safe_count}")
# print(f"sum vulnarable smart contract: {vul_count}")
# print('======>> '.join(tools))