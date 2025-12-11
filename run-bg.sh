#!/bin/bash
git pull
npm i
node index.js >anywhere.log 2>&1 &
