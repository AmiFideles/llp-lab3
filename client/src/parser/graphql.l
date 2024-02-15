%{
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <stdbool.h>
  #include "graphql_parser.h"
  #include "../parser/ast.h"

  extern FILE* yyin;

  void init_flex(FILE* infile) {
    yyrestart(infile);
  }

%}

query             "query"
mutation          "mutation"
true_value        "true"
false_value       "false"
null_value        "null"
field             [a-zA-Z_][a-zA-Z0-9_]*[!]?
variable          \$[a-zA-Z_][a-zA-Z0-9_]*
number            [-+]?[0-9]*\.?[0-9]+([Ee][-+]?[0-9]+)?
string            [\"\'"][^\"]*[\"\'"]
comment            #.*$
%%

{query}                                 { return QUERY_TOKEN; }
{mutation}                              { return MUTATION_TOKEN; }
{null_value}                            { return NULL_VALUE_TOKEN; }


[=]                                     { return EQUAL_TOKEN; }
[(]                                     { return BRAKET_OPEN_TOKEN; }
[)]                                     { return BRAKET_CLOSE_TOKEN; }
[{]                                     { return CURLY_BRACE_OPEN_TOKEN; }
[}]                                     { return CURLY_BRACE_CLOSE_TOKEN; }
[\[]                                    { return SQUARE_BRAKET_OPEN_TOKEN; }
[\]]                                    { return SQUARE_BRAKET_CLOSE_TOKEN; }
[,]                                     { return COMMA_TOKEN; }
[.]                                     { return DOT_TOKEN; }

"=="                                    { return EQUAL_OPERATOR_TOKEN; }
"!="                                    { return NOT_EQUAL_TOKEN; }
[!]                                     { return NOT_TOKEN; }

[\"\'"]                                 { return QUERY_TOKEN; }

[<]                                     { return LOWER_OPERATOR_TOKEN; }
[>]                                     { return GREATER_OPERATOR_TOKEN; }
">="                                    { return GREATER_EQUAL_TOKEN; }
"<="                                    { return LOWER_EQUAL_TOKEN; }

[+]                                     { return PLUS_OPERATION_TOKEN; }
[-]                                     { return MINUS_OPERATION_TOKEN; }
[*]                                     { return MULTIPLY_OPERATION_TOKEN; }
[/]                                     { return DIVIDE_OPERATION_TOKEN; }

"||"                                    { return OR_TOKEN; }
"&&"                                    { return AND_TOKEN; }

{true_value}                            { yylval.boolean = 1; return BOOLEAN_TOKEN; }
{false_value}                           { yylval.boolean = 0; return BOOLEAN_TOKEN; }

[-]?[0-9]+                              { yylval.integer = atoi(yytext); return INTEGER_TOKEN; }
[-]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?   { yylval.real = atof(yytext); return DOUBLE_TOKEN; }

[;]                                     { return RET_TOKEN; }
[\:]                                    { return DOUBLE_DOT_TOKEN; }
[ \t\n\r]+                              { /* Ignore whitespace */ }

{field}                                 { yylval.string = yytext; return FIELD_TOKEN; }
{variable}                              { yylval.string = yytext; return VARIABLE_TOKEN; }
{string}                                { yylval.string = yytext; return STRING_TOKEN; }
{comment}                               { /* Ignore comment */ }
.                                       { printf("ERROR: Unexpected character '%s'\n", yytext); exit(1); }

%%

int yywrap() {
  return 1;
}