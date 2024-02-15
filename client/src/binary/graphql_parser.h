/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_HOME_ASUS_LLP_TEST_LLP_LAB_3_LLP_CLIENT_SRC_BINARY_GRAPHQL_PARSER_H_INCLUDED
# define YY_YY_HOME_ASUS_LLP_TEST_LLP_LAB_3_LLP_CLIENT_SRC_BINARY_GRAPHQL_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 1 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"

  #include "../parser/ast.h"

#line 53 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.h"

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    QUERY_TOKEN = 258,             /* QUERY_TOKEN  */
    MUTATION_TOKEN = 259,          /* MUTATION_TOKEN  */
    BOOLEAN_TOKEN = 260,           /* BOOLEAN_TOKEN  */
    NULL_VALUE_TOKEN = 261,        /* NULL_VALUE_TOKEN  */
    FIELD_TOKEN = 262,             /* FIELD_TOKEN  */
    VARIABLE_TOKEN = 263,          /* VARIABLE_TOKEN  */
    NUMBER_TOKEN = 264,            /* NUMBER_TOKEN  */
    STRING_TOKEN = 265,            /* STRING_TOKEN  */
    PARENTHESIS_TOKEN = 266,       /* PARENTHESIS_TOKEN  */
    COLON_TOKEN = 267,             /* COLON_TOKEN  */
    EQUAL_TOKEN = 268,             /* EQUAL_TOKEN  */
    BRAKET_OPEN_TOKEN = 269,       /* BRAKET_OPEN_TOKEN  */
    BRAKET_CLOSE_TOKEN = 270,      /* BRAKET_CLOSE_TOKEN  */
    CURLY_BRACE_OPEN_TOKEN = 271,  /* CURLY_BRACE_OPEN_TOKEN  */
    CURLY_BRACE_CLOSE_TOKEN = 272, /* CURLY_BRACE_CLOSE_TOKEN  */
    COMMA_TOKEN = 273,             /* COMMA_TOKEN  */
    DOT_TOKEN = 274,               /* DOT_TOKEN  */
    EQUAL_OPERATOR_TOKEN = 275,    /* EQUAL_OPERATOR_TOKEN  */
    LOWER_OPERATOR_TOKEN = 276,    /* LOWER_OPERATOR_TOKEN  */
    GREATER_OPERATOR_TOKEN = 277,  /* GREATER_OPERATOR_TOKEN  */
    GREATER_EQUAL_TOKEN = 278,     /* GREATER_EQUAL_TOKEN  */
    LOWER_EQUAL_TOKEN = 279,       /* LOWER_EQUAL_TOKEN  */
    NOT_EQUAL_TOKEN = 280,         /* NOT_EQUAL_TOKEN  */
    NOT_TOKEN = 281,               /* NOT_TOKEN  */
    OR_TOKEN = 282,                /* OR_TOKEN  */
    AND_TOKEN = 283,               /* AND_TOKEN  */
    INTEGER_TOKEN = 284,           /* INTEGER_TOKEN  */
    DOUBLE_TOKEN = 285,            /* DOUBLE_TOKEN  */
    IDENTIFIER_TOKEN = 286,        /* IDENTIFIER_TOKEN  */
    PLUS_OPERATION_TOKEN = 287,    /* PLUS_OPERATION_TOKEN  */
    MINUS_OPERATION_TOKEN = 288,   /* MINUS_OPERATION_TOKEN  */
    MULTIPLY_OPERATION_TOKEN = 289, /* MULTIPLY_OPERATION_TOKEN  */
    DIVIDE_OPERATION_TOKEN = 290,  /* DIVIDE_OPERATION_TOKEN  */
    RET_TOKEN = 291,               /* RET_TOKEN  */
    DOUBLE_DOT_TOKEN = 292,        /* DOUBLE_DOT_TOKEN  */
    QOUTE_TOKEN = 293,             /* QOUTE_TOKEN  */
    SQUARE_BRAKET_OPEN_TOKEN = 294, /* SQUARE_BRAKET_OPEN_TOKEN  */
    SQUARE_BRAKET_CLOSE_TOKEN = 295 /* SQUARE_BRAKET_CLOSE_TOKEN  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 16 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"

  int integer;
  int boolean;
  double real;
  char *string;
  Node *node;

#line 118 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_HOME_ASUS_LLP_TEST_LLP_LAB_3_LLP_CLIENT_SRC_BINARY_GRAPHQL_PARSER_H_INCLUDED  */
