#!/usr/bin/python3
# -*- coding: utf-8 -*-

__title__ = "eCLAT"
__version__ = "2.0"
__status__ = "unreleased"
__author__ = "Andrea Bernini"
__date__ = "2021 Aprile 26"


from os import path
import sys
import re
from eCLAT_Code.Code.lexer import Lexer
from eCLAT_Code.Code.parser import Parser
import argparse

class Environment(object):
    def __init__(self):
        self.variables = {}

def run_file(args):
    fname = args
    # prende il nome del package
    package_name = fname.split("/")[-1].split(".")[0]
    with open(fname) as f:
        text_input = f.read()
    lexer = Lexer().get_lexer()
    tokens = detect_indent(lexer, text_input)
    #for i in tokens:
    #    print(i)
    pg = Parser(package_name=package_name)
    pg.parse()
    parser = pg.get_parser()
    parser.parse(tokens).exec(Environment())


# ------------------------------------------- #
# Rimuove i commenti dalla stringa passata    #
# come argomento                              #
def remove_comment(line):
    # RegEx per i commenti
    comments = r'(#.*)(?:\n|\Z)'
    comment = re.search(comments, line)
    while comment is not None:
        start, end = comment.span(1)
        assert start >= 0 and end >= 0
        # rimuovi la stringa che matcha con il commento
        line = line[0:start] + line[end:]
        comment = re.search(comments, line)
    return line

# ------------------------------------------- #
# Ritorna il valore dell'indentazione         #
def indentation(s, tabsize=4):
    sx = s.expandtabs(tabsize)
    return 0 if sx.isspace() else len(sx) - len(sx.lstrip())

# ------------------------------------------- #
# Controlla che il file sia indentato         #
# correttamente                               #
def detect_indent(lexer, source):
    block = False
    indent_space = 4
    indent_stack = [0]
    dedent = ""
    text = ""
    for line_num, line in enumerate(source.splitlines(), 0):
        line = line.rstrip()
        line = line.replace("\t", " "*indent_space)
        # ------------------------------------------- #
        # rimuovo i commenti dalla riga               #
        line = remove_comment(line)
        # ------------------------------------------- #
        # Se la riga non è vuota                      #
        if line.strip():
            # ------------------------------------------- #
            # Calcolo il valore dell'indentazione         #
            indent_number = indentation(line, indent_space)

            # ------------------------------------------- #
            # Se l'indentazione trovata è diversa dall'   #
            # ultimo elemento dello stack, e non sono     #
            # alla riga successiva ad una apertura di un  #
            # blocco (:),  significa che forse si sta     #
            # "chiudendo" un blocco, perciò controllo che #
            # sia in modulo 4
            if indent_number != indent_stack[-1]:
                if not block and indent_number < indent_stack[-1] and indent_number % indent_space == 0:
                    while indent_stack[-1] != indent_number:
                        indent_stack.pop()
                        dedent += " _dedent "
                    line = dedent + line
                    dedent = ""
                else:
                    raise IndentationError("at line " + str(1+line_num))

            if block:
                line = " _indent " + line
                block = False

            # ------------------------------------------- #
            # Se lo statement successivo è un Block (:)   #
            if line[len(line)-1:len(line)] == ":":
                indent_stack.append(indent_stack[-1]+indent_space)
                block = True
            text = text + line +"\n"

    # ------------------------------------------- #
    # Inserisco gli eventuali dedent rimasti      #
    for dedent in range(len(indent_stack)-1):
        text += " _dedent "
    return lexer.lex(text)


######### PER DEBUG ##########
#run_file("eCLAT_Code/Examples/Test_1/test_1.eclat")
#run_file("Examples/classificatore.eclat")
#run_file("eCLAT_Code/Examples/path_tracing.eclat")
##############################

#"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('--run', type=run_file, help='Interpreter')

    args = parser.parse_args()
#"""