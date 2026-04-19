#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : delta_time.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 18 aug 2025


def delta_time(delta_t, units=["hours", "minutes", "seconds", "miliseconds"]):
    out = ""
    if delta_t // 3600 != 0:  # hours
        out = out + str(int(delta_t // 3600)) + " " + units[0]
        delta_t = delta_t % 3600
    if delta_t // 60 != 0:  # minutes
        out = out + " " + str(int(delta_t // 60)) + " " + units[1]
        delta_t = delta_t % 60
    if int(delta_t) != 0:  # seconds
        out = out + " " + str(int(delta_t)) + " " + units[2]
        delta_t = delta_t - int(delta_t)
    if delta_t // 0.001 != 0:  # miliseconds
        out = out + " " + str(int(delta_t // 0.001)) + " " + units[3]
    if out == "":
        out = "0 " + units[-1]
    out = out + "."
    if out.startswith(" "):
        out = out[1:]
    return out
