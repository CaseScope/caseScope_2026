#!/usr/bin/env python3
"""Build the Huntress IOC extraction training dataset."""

import importlib.util
import os

_dataset_spec = importlib.util.spec_from_file_location(
    "ioc_training_dataset_shared",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "utils", "ioc_training_dataset.py"),
)
_dataset_module = importlib.util.module_from_spec(_dataset_spec)
_dataset_spec.loader.exec_module(_dataset_module)
main = _dataset_module.main


if __name__ == "__main__":
    main()
