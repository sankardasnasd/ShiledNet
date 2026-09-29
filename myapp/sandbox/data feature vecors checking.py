import pandas as pd

path = r"C:\Users\GAYATHRI\Downloads\Shieldnet main\APP MALWARE\CSV\feature_vectors_static.csv"

df = pd.read_csv(path)

print("====================================")
print("DATASET INFORMATION")
print("====================================")

print("Rows:", df.shape[0])
print("Columns:", df.shape[1])

print("\nFirst 30 columns:")
for column in df.columns[:30]:
    print(column)

print("\nPossible LABEL columns:")
for column in df.columns:
    name = str(column).lower()

    if any(word in name for word in [
        "label",
        "class",
        "category",
        "malware",
        "benign",
        "type",
        "family"
    ]):
        print(column)

print("\nNon-numeric columns:")
for column in df.columns:
    if df[column].dtype == "object":
        print(column)

print("\nIndex-like columns:")
for column in df.columns[:10]:
    print(
        column,
        "->",
        df[column].dtype,
        "unique:",
        df[column].nunique()
    )