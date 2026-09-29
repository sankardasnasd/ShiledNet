import pandas as pd

file_path = r"C:\Users\GAYATHRI\PycharmProjects\SHIELDNET\PhiUSIIL_Phishing_URL_Dataset.csv"

df = pd.read_csv(file_path)

print("=" * 60)
print("DATASET SHAPE")
print("=" * 60)
print(df.shape)

print("\n" + "=" * 60)
print("COLUMNS")
print("=" * 60)

for column in df.columns:
    print(column)

print("\n" + "=" * 60)
print("FIRST 5 ROWS")
print("=" * 60)

print(df.head())

print("\n" + "=" * 60)
print("DATA TYPES")
print("=" * 60)

print(df.dtypes)

print("\n" + "=" * 60)
print("MISSING VALUES")
print("=" * 60)

print(df.isnull().sum())

print("\n" + "=" * 60)
print("LABEL DISTRIBUTION")
print("=" * 60)

print(df["label"].value_counts())