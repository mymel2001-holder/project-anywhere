#!/bin/bash
git pull
npm i
node index.mjs >anywhere.log 2>&1 &
