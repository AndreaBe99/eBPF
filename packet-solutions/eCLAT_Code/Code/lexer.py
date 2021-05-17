from rply import LexerGenerator
import re
import csv
from eCLAT_Code.Code.path import Path
token_list = []

class Lexer():
    def __init__(self):
        self.lexer = LexerGenerator()

    def _add_tokens(self):
        with open(Path.token_path, mode='r') as csv_file:
            str = csv.reader(csv_file, delimiter = ';')
            for row in str:
                token_list.append(row[0])
                exec("self.lexer.add('" + row[0] + "', " + row[1] + ")")
        token_list.append('$end')

        # Ignore spaces
        self.lexer.ignore('[ \t\r\f\v]+')

    def get_lexer(self):
        self._add_tokens()
        return self.lexer.build() 
