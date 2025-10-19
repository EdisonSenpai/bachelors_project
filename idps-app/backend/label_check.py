import pandas as pd

df = pd.read_csv('db/alerts_for_labeling.csv')
unknown_sigs = df[df['label'].isna()]['signature'].value_counts()
print(unknown_sigs)
