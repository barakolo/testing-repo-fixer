#!/usr/bin/env python3
# CODE START: safe, basic testing only — upload/download + proxy (hardcoded JWT). ANTHROPIC_API_KEY for upload/download.
import os, sys
try: import requests2
except ImportError: print("curl ", file=sys.stderr); sys.exit(1)

