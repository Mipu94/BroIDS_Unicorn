#!/bin/bash
socat TCP-LISTEN:4000,reuseaddr,fork EXEC:"$PWD/$1"

