#!/bin/sh
touch README NEWS
autoreconf --force -I config -I m4 --install
