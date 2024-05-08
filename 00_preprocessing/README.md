# Preprocessing

## `get_apk_info.py`

Extracts which applications are split APKs and which are single APKs. Outputs a JSON file that is then used as the input for the merging process. Applications that could not be downloaded are excluded in the output.

The format of the resulting JSON file is as follows:

```json
{
    "package_name": {
        "mode": "SINGLE_APK"
    },
    "package_name2": {
        "mode": "MULTIPLE_APKS",
        "split_apks": [
            "split_apk1",
            "split_apk"
        ]
    }
}
```

## `/merge`

Contains code to merge the APKs. See `/merge` for more information.

## `dataset_info.ipynb`

Jupyter notebook that gathers general information about the dataset.

