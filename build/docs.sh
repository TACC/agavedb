#!/bin/bash

export PYTHONPATH=$PYTHONPATH:$PWD

cd ../ ; pydocmd simple agavedb.keyval+++ > docs/api.md
