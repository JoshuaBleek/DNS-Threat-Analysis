#!/usr/bin/env python3
# Frequency Counter Object - Mark Baggett @markbaggett
# This object is used to count the frequency of characters appearance in text.
# See https://isc.sans.edu/diary/Detecting+Random+-+Finding+Algorithmically+chosen+DNS+names+%28DGA%29/19893
import pickle
import argparse
import os
import sys
import shutil

class CharCount(dict):
    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = 0
        return value

class FreqCounter(dict):
    def __init__(self, *args, **kargs):
        self.ignorechars = """\n\t\r~@#%^&*"'/\-+<>{}|$!:()[];?="""
        self.ignorecase = True
        super(FreqCounter, self).__init__(*args, **kargs)

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = CharCount()
        return value

    def tally_str(self, line, weight=1):
        wordcount = 0
        if self.ignorecase:
            line = line.lower()
        for char in range(len(line)-1):
            if line[char] in self.ignorechars or line[char+1] in self.ignorechars:
                continue
            if line[char+1] in self[line[char]]:
                self[line[char]][line[char+1]] = self[line[char]][line[char+1]] + (1*weight)
            else:
                self[line[char]][line[char+1]] = weight
        return wordcount

    def probability(self, string, max_prob=40):
        probs = []
        for pos, ch in enumerate(string[:-1]):
            if ch not in self.ignorechars and string[pos+1] not in self.ignorechars:
                probs.append(self._probability(ch, string[pos+1], max_prob))
        if len(probs) == 0:
            return 0
        return sum(probs) / len(probs)

    def printtable(self):
        print("def lookupfreq(index):")
        print("    #Although it may not aways be the past data collected. The current setting for this file are:")
        print("    #The following characters are currently ignored: " + repr(self.ignorechars))
        if self.ignorecase:
            print("    #It currently ignores case for all calculations.")
        else:
            print("    #It is currently case sensitive for all calculations.")
        print("    return {")
        for keys in sorted(self.keys(), reverse=True, key=self.get):
            print("    \"" + str(keys) + "\":", end=" ")
            letters = ""
            for subkeys in sorted(self[keys].keys(), reverse=True, key=self[keys].get):
                letters += subkeys
            print(repr(letters) + ',')
        print("    }[index]")

    def lookup(self, letter):
        if self.ignorecase:
            letter = letter.lower()
        return "".join(sorted(self[letter].keys(), reverse=True, key=self[letter].get))

    def _probability(self, top, sub, max_prob=40):
        if self.ignorecase:
            top = top.lower()
            sub = sub.lower()
        if top not in self:
            return 0
        all_letter_count = sum(self[top].values())
        char2_count = 0
        if sub in self[top]:
            char2_count = self[top][sub]
        probab = float(char2_count) / float(all_letter_count) * 100
        if probab > max_prob:
            probab = max_prob
        return probab

    def printraw(self):
        print(self)

    def save(self, filename):
        try:
            file_handle = open(filename, 'wb')
            data = [list(self.items()), self.ignorechars, self.ignorecase]
            pickle.dump(data, file_handle)
            file_handle.flush()
            file_handle.close()
        except Exception as e:
            print("Unable to write freq file :" + str(e))

    def load(self, filename):
        try:
            file_handle = open(filename, 'rb')
            stored_values = pickle.load(file_handle)
            self.update(stored_values[0])
            self.ignorechars = stored_values[1]
            self.ignorecase = stored_values[2]
        except Exception as e:
            print("Unable to load freq file :" + str(e))

    def promote(self, top, sub, weight):
        chartable = self[top]
        currentoffset = self.lookup(top).index(sub)
        if currentoffset < weight:
            current
