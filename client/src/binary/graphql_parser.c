/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 5 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"

  #include <stdio.h>
  #include <stdlib.h>
  #include "graphql_parser.h"

  extern void yyerror (char const *);
  extern int yylex(void);

  extern FILE *yyin;

#line 82 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "graphql_parser.h"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_QUERY_TOKEN = 3,                /* QUERY_TOKEN  */
  YYSYMBOL_MUTATION_TOKEN = 4,             /* MUTATION_TOKEN  */
  YYSYMBOL_BOOLEAN_TOKEN = 5,              /* BOOLEAN_TOKEN  */
  YYSYMBOL_NULL_VALUE_TOKEN = 6,           /* NULL_VALUE_TOKEN  */
  YYSYMBOL_FIELD_TOKEN = 7,                /* FIELD_TOKEN  */
  YYSYMBOL_VARIABLE_TOKEN = 8,             /* VARIABLE_TOKEN  */
  YYSYMBOL_NUMBER_TOKEN = 9,               /* NUMBER_TOKEN  */
  YYSYMBOL_STRING_TOKEN = 10,              /* STRING_TOKEN  */
  YYSYMBOL_PARENTHESIS_TOKEN = 11,         /* PARENTHESIS_TOKEN  */
  YYSYMBOL_COLON_TOKEN = 12,               /* COLON_TOKEN  */
  YYSYMBOL_EQUAL_TOKEN = 13,               /* EQUAL_TOKEN  */
  YYSYMBOL_BRAKET_OPEN_TOKEN = 14,         /* BRAKET_OPEN_TOKEN  */
  YYSYMBOL_BRAKET_CLOSE_TOKEN = 15,        /* BRAKET_CLOSE_TOKEN  */
  YYSYMBOL_CURLY_BRACE_OPEN_TOKEN = 16,    /* CURLY_BRACE_OPEN_TOKEN  */
  YYSYMBOL_CURLY_BRACE_CLOSE_TOKEN = 17,   /* CURLY_BRACE_CLOSE_TOKEN  */
  YYSYMBOL_COMMA_TOKEN = 18,               /* COMMA_TOKEN  */
  YYSYMBOL_DOT_TOKEN = 19,                 /* DOT_TOKEN  */
  YYSYMBOL_EQUAL_OPERATOR_TOKEN = 20,      /* EQUAL_OPERATOR_TOKEN  */
  YYSYMBOL_LOWER_OPERATOR_TOKEN = 21,      /* LOWER_OPERATOR_TOKEN  */
  YYSYMBOL_GREATER_OPERATOR_TOKEN = 22,    /* GREATER_OPERATOR_TOKEN  */
  YYSYMBOL_GREATER_EQUAL_TOKEN = 23,       /* GREATER_EQUAL_TOKEN  */
  YYSYMBOL_LOWER_EQUAL_TOKEN = 24,         /* LOWER_EQUAL_TOKEN  */
  YYSYMBOL_NOT_EQUAL_TOKEN = 25,           /* NOT_EQUAL_TOKEN  */
  YYSYMBOL_NOT_TOKEN = 26,                 /* NOT_TOKEN  */
  YYSYMBOL_OR_TOKEN = 27,                  /* OR_TOKEN  */
  YYSYMBOL_AND_TOKEN = 28,                 /* AND_TOKEN  */
  YYSYMBOL_INTEGER_TOKEN = 29,             /* INTEGER_TOKEN  */
  YYSYMBOL_DOUBLE_TOKEN = 30,              /* DOUBLE_TOKEN  */
  YYSYMBOL_IDENTIFIER_TOKEN = 31,          /* IDENTIFIER_TOKEN  */
  YYSYMBOL_PLUS_OPERATION_TOKEN = 32,      /* PLUS_OPERATION_TOKEN  */
  YYSYMBOL_MINUS_OPERATION_TOKEN = 33,     /* MINUS_OPERATION_TOKEN  */
  YYSYMBOL_MULTIPLY_OPERATION_TOKEN = 34,  /* MULTIPLY_OPERATION_TOKEN  */
  YYSYMBOL_DIVIDE_OPERATION_TOKEN = 35,    /* DIVIDE_OPERATION_TOKEN  */
  YYSYMBOL_RET_TOKEN = 36,                 /* RET_TOKEN  */
  YYSYMBOL_DOUBLE_DOT_TOKEN = 37,          /* DOUBLE_DOT_TOKEN  */
  YYSYMBOL_QOUTE_TOKEN = 38,               /* QOUTE_TOKEN  */
  YYSYMBOL_SQUARE_BRAKET_OPEN_TOKEN = 39,  /* SQUARE_BRAKET_OPEN_TOKEN  */
  YYSYMBOL_SQUARE_BRAKET_CLOSE_TOKEN = 40, /* SQUARE_BRAKET_CLOSE_TOKEN  */
  YYSYMBOL_YYACCEPT = 41,                  /* $accept  */
  YYSYMBOL_start = 42,                     /* start  */
  YYSYMBOL_operation_definitions = 43,     /* operation_definitions  */
  YYSYMBOL_operation_definition = 44,      /* operation_definition  */
  YYSYMBOL_json_input = 45,                /* json_input  */
  YYSYMBOL_json_value = 46,                /* json_value  */
  YYSYMBOL_json_object = 47,               /* json_object  */
  YYSYMBOL_json_array = 48,                /* json_array  */
  YYSYMBOL_json_elements = 49,             /* json_elements  */
  YYSYMBOL_json_element = 50,              /* json_element  */
  YYSYMBOL_json_values = 51,               /* json_values  */
  YYSYMBOL_query = 52,                     /* query  */
  YYSYMBOL_mutation = 53,                  /* mutation  */
  YYSYMBOL_selection_set_opt = 54,         /* selection_set_opt  */
  YYSYMBOL_selection_set = 55,             /* selection_set  */
  YYSYMBOL_selection_list = 56,            /* selection_list  */
  YYSYMBOL_selection = 57,                 /* selection  */
  YYSYMBOL_arguments_opt = 58,             /* arguments_opt  */
  YYSYMBOL_arguments = 59,                 /* arguments  */
  YYSYMBOL_argument_list = 60,             /* argument_list  */
  YYSYMBOL_argument = 61,                  /* argument  */
  YYSYMBOL_value = 62,                     /* value  */
  YYSYMBOL_rel_expr = 63,                  /* rel_expr  */
  YYSYMBOL_expr = 64,                      /* expr  */
  YYSYMBOL_mul_expr = 65,                  /* mul_expr  */
  YYSYMBOL_atomic_expr = 66,               /* atomic_expr  */
  YYSYMBOL_name = 67,                      /* name  */
  YYSYMBOL_variable = 68,                  /* variable  */
  YYSYMBOL_string = 69                     /* string  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  37
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   126

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  41
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  29
/* YYNRULES -- Number of rules.  */
#define YYNRULES  64
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  102

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   295


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint8 yyrline[] =
{
       0,   102,   102,   103,   104,   108,   109,   113,   114,   119,
     122,   123,   124,   128,   129,   133,   134,   138,   139,   143,
     147,   148,   152,   156,   160,   161,   165,   169,   170,   174,
     177,   178,   182,   186,   187,   191,   192,   193,   194,   195,
     196,   197,   198,   202,   203,   204,   207,   208,   209,   210,
     211,   212,   213,   217,   218,   219,   223,   224,   225,   229,
     230,   231,   235,   238,   241
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "QUERY_TOKEN",
  "MUTATION_TOKEN", "BOOLEAN_TOKEN", "NULL_VALUE_TOKEN", "FIELD_TOKEN",
  "VARIABLE_TOKEN", "NUMBER_TOKEN", "STRING_TOKEN", "PARENTHESIS_TOKEN",
  "COLON_TOKEN", "EQUAL_TOKEN", "BRAKET_OPEN_TOKEN", "BRAKET_CLOSE_TOKEN",
  "CURLY_BRACE_OPEN_TOKEN", "CURLY_BRACE_CLOSE_TOKEN", "COMMA_TOKEN",
  "DOT_TOKEN", "EQUAL_OPERATOR_TOKEN", "LOWER_OPERATOR_TOKEN",
  "GREATER_OPERATOR_TOKEN", "GREATER_EQUAL_TOKEN", "LOWER_EQUAL_TOKEN",
  "NOT_EQUAL_TOKEN", "NOT_TOKEN", "OR_TOKEN", "AND_TOKEN", "INTEGER_TOKEN",
  "DOUBLE_TOKEN", "IDENTIFIER_TOKEN", "PLUS_OPERATION_TOKEN",
  "MINUS_OPERATION_TOKEN", "MULTIPLY_OPERATION_TOKEN",
  "DIVIDE_OPERATION_TOKEN", "RET_TOKEN", "DOUBLE_DOT_TOKEN", "QOUTE_TOKEN",
  "SQUARE_BRAKET_OPEN_TOKEN", "SQUARE_BRAKET_CLOSE_TOKEN", "$accept",
  "start", "operation_definitions", "operation_definition", "json_input",
  "json_value", "json_object", "json_array", "json_elements",
  "json_element", "json_values", "query", "mutation", "selection_set_opt",
  "selection_set", "selection_list", "selection", "arguments_opt",
  "arguments", "argument_list", "argument", "value", "rel_expr", "expr",
  "mul_expr", "atomic_expr", "name", "variable", "string", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-35)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int8 yypact[] =
{
      11,     4,     4,   -35,   -35,    40,    49,   -35,   -35,    58,
      19,    11,   -35,    57,   -35,   -35,   -35,   -35,   -35,   -35,
      90,    73,    84,   -35,   -35,   -35,   -35,     3,   -35,   -10,
     -35,   103,   -35,   -29,   -35,   -35,   -11,   -35,   -35,   -35,
     -35,    57,    40,    40,    40,    40,    40,    40,    40,    40,
      40,    40,   100,     8,   -35,   -35,   -35,    28,    70,    70,
     -35,    73,    73,    73,    73,    73,    73,    84,    84,   -35,
     -35,   -35,    18,   -35,    80,    -9,     4,   -35,   -35,   -35,
     -35,   -35,   -35,   100,    28,    28,    28,    28,     2,    28,
      13,   -35,   -35,   -35,   -35,   -35,   -35,   -35,   -35,   -35,
     -35,   -35
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     0,     0,    62,    64,     0,     0,    61,    60,     0,
       0,     0,     5,     0,     9,    12,    11,     7,     8,    10,
      43,    46,    53,    56,    44,    45,    22,    30,    23,     0,
      13,     0,    17,     0,    15,    20,     0,     1,     4,     6,
       3,     2,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    24,    31,    59,    14,     0,     0,     0,
      16,    51,    47,    48,    50,    49,    52,    54,    55,    57,
      58,    63,     0,    33,     0,    41,     0,    29,    25,    18,
      19,    21,    32,     0,     0,     0,     0,     0,     0,     0,
       0,    27,    34,    37,    38,    39,    40,    35,    36,    42,
      26,    28
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -35,   -35,    24,    -7,    15,    -6,   -35,   -35,   -35,   -18,
     -35,   -35,   -35,   -35,   -35,   -35,     0,   -35,   -35,   -35,
     -34,     7,   -35,     1,    74,    75,    -1,   -26,   -35
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,    10,    11,    12,    13,    14,    15,    16,    31,    32,
      36,    17,    18,    77,    78,    90,    26,    53,    54,    72,
      73,    19,    20,    21,    22,    23,    24,    75,    25
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
{
      27,    27,    28,    35,    39,    55,    29,    59,    58,     3,
      71,     3,     4,    33,     1,     2,     5,    52,     3,    37,
       3,     4,    48,    49,    76,     5,    40,     6,    89,    60,
     100,     7,     8,    82,    39,     3,    83,    41,     4,    79,
       7,     8,     5,    61,    62,    63,    64,    65,    66,    92,
       9,    74,    80,    81,     5,    38,     3,     7,     8,     4,
       1,     2,    98,     5,    33,     3,    30,     0,     4,     7,
       8,     0,     5,     0,     6,    27,    91,     3,     7,     8,
       4,     0,    74,     0,     5,     0,     6,     7,     8,    27,
     101,    93,    94,    95,    96,    97,    99,     9,    34,     7,
       8,    84,    85,    86,    87,    48,    49,     3,    71,     9,
      42,    43,    44,    45,    46,    47,     0,    88,    50,    51,
      56,    57,    67,    68,     0,    69,    70
};

static const yytype_int8 yycheck[] =
{
       1,     2,     2,     9,    11,    15,     5,    18,    37,     7,
       8,     7,    10,     6,     3,     4,    14,    14,     7,     0,
       7,    10,    32,    33,    16,    14,    11,    16,    37,    40,
      17,    29,    30,    15,    41,     7,    18,    13,    10,    57,
      29,    30,    14,    42,    43,    44,    45,    46,    47,    83,
      39,    52,    58,    59,    14,    36,     7,    29,    30,    10,
       3,     4,    88,    14,    57,     7,    17,    -1,    10,    29,
      30,    -1,    14,    -1,    16,    76,    76,     7,    29,    30,
      10,    -1,    83,    -1,    14,    -1,    16,    29,    30,    90,
      90,    84,    85,    86,    87,    88,    89,    39,    40,    29,
      30,    21,    22,    23,    24,    32,    33,     7,     8,    39,
      20,    21,    22,    23,    24,    25,    -1,    37,    34,    35,
      17,    18,    48,    49,    -1,    50,    51
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     3,     4,     7,    10,    14,    16,    29,    30,    39,
      42,    43,    44,    45,    46,    47,    48,    52,    53,    62,
      63,    64,    65,    66,    67,    69,    57,    67,    57,    64,
      17,    49,    50,    62,    40,    46,    51,     0,    36,    44,
      45,    43,    20,    21,    22,    23,    24,    25,    32,    33,
      34,    35,    14,    58,    59,    15,    17,    18,    37,    18,
      40,    64,    64,    64,    64,    64,    64,    65,    65,    66,
      66,     8,    60,    61,    67,    68,    16,    54,    55,    50,
      46,    46,    15,    18,    21,    22,    23,    24,    37,    37,
      56,    57,    61,    62,    62,    62,    62,    62,    68,    62,
      17,    57
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    41,    42,    42,    42,    43,    43,    44,    44,    45,
      46,    46,    46,    47,    47,    48,    48,    49,    49,    50,
      51,    51,    52,    53,    54,    54,    55,    56,    56,    57,
      58,    58,    59,    60,    60,    61,    61,    61,    61,    61,
      61,    61,    61,    62,    62,    62,    63,    63,    63,    63,
      63,    63,    63,    64,    64,    64,    65,    65,    65,    66,
      66,    66,    67,    68,    69
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     2,     2,     2,     1,     2,     1,     1,     1,
       1,     1,     1,     2,     3,     2,     3,     1,     3,     3,
       1,     3,     2,     2,     0,     1,     3,     1,     2,     3,
       0,     1,     3,     1,     3,     3,     3,     3,     3,     3,
       3,     1,     3,     1,     1,     1,     1,     3,     3,     3,
       3,     3,     3,     1,     3,     3,     1,     3,     3,     3,
       1,     1,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* start: json_input operation_definitions  */
#line 102 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { addJsonInput((yyvsp[-1].node)); addRequest((yyvsp[0].node)); }
#line 1220 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 3: /* start: operation_definitions json_input  */
#line 103 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { addJsonInput((yyvsp[0].node)); addRequest((yyvsp[-1].node)); }
#line 1226 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 4: /* start: start RET_TOKEN  */
#line 104 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { return 0;}
#line 1232 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 5: /* operation_definitions: operation_definition  */
#line 108 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[0].node); }
#line 1238 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 6: /* operation_definitions: operation_definitions operation_definition  */
#line 109 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(OPERATION, (yyvsp[-1].node), (yyvsp[0].node)); }
#line 1244 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 7: /* operation_definition: query  */
#line 113 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(OPERATION, (yyvsp[0].node), NULL); }
#line 1250 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 8: /* operation_definition: mutation  */
#line 114 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(OPERATION, (yyvsp[0].node), NULL); }
#line 1256 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 9: /* json_input: json_value  */
#line 119 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(JSON, (yyvsp[0].node), NULL); }
#line 1262 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 10: /* json_value: value  */
#line 122 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
          { (yyval.node) = (yyvsp[0].node); }
#line 1268 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 11: /* json_value: json_array  */
#line 123 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                { (yyval.node) = (yyvsp[0].node); }
#line 1274 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 12: /* json_value: json_object  */
#line 124 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                 { (yyval.node) = (yyvsp[0].node); }
#line 1280 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 13: /* json_object: CURLY_BRACE_OPEN_TOKEN CURLY_BRACE_CLOSE_TOKEN  */
#line 128 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                   { (yyval.node) = NULL; }
#line 1286 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 14: /* json_object: CURLY_BRACE_OPEN_TOKEN json_elements CURLY_BRACE_CLOSE_TOKEN  */
#line 129 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                                 { (yyval.node) = createNode_V(JSON_OBJECT, (yyvsp[-1].node), NULL); }
#line 1292 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 15: /* json_array: SQUARE_BRAKET_OPEN_TOKEN SQUARE_BRAKET_CLOSE_TOKEN  */
#line 133 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                       { (yyval.node) = createNode_V(JSON_ARRAY, NULL, NULL); }
#line 1298 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 16: /* json_array: SQUARE_BRAKET_OPEN_TOKEN json_values SQUARE_BRAKET_CLOSE_TOKEN  */
#line 134 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                                   { (yyval.node) = createNode_V(JSON_ARRAY, (yyvsp[-1].node), NULL); }
#line 1304 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 17: /* json_elements: json_element  */
#line 138 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                 { (yyval.node) = (yyvsp[0].node); }
#line 1310 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 18: /* json_elements: json_elements COMMA_TOKEN json_element  */
#line 139 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                           { (yyval.node) = createNode_V(JSON_ELEMENTS, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1316 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 19: /* json_element: value DOUBLE_DOT_TOKEN json_value  */
#line 143 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                      { (yyval.node) = createNode_V(JSON_ELEMENT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1322 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 20: /* json_values: json_value  */
#line 147 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
               { (yyval.node) = (yyvsp[0].node); }
#line 1328 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 21: /* json_values: json_values COMMA_TOKEN json_value  */
#line 148 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                       { (yyval.node) = createNode_V(VALUES, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1334 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 22: /* query: QUERY_TOKEN selection  */
#line 152 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(QUERY, (yyvsp[0].node), NULL); }
#line 1340 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 23: /* mutation: MUTATION_TOKEN selection  */
#line 156 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(MUTATION, (yyvsp[0].node), NULL); }
#line 1346 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 24: /* selection_set_opt: %empty  */
#line 160 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
    { (yyval.node) = NULL; }
#line 1352 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 26: /* selection_set: CURLY_BRACE_OPEN_TOKEN selection_list CURLY_BRACE_CLOSE_TOKEN  */
#line 165 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                                  { (yyval.node) = createNode_V(SELECTION_SET, (yyvsp[-1].node), NULL); }
#line 1358 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 27: /* selection_list: selection  */
#line 169 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[0].node); }
#line 1364 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 28: /* selection_list: selection_list selection  */
#line 170 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(SELECTION, (yyvsp[-1].node), (yyvsp[0].node)); }
#line 1370 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 29: /* selection: name arguments_opt selection_set_opt  */
#line 174 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                         { Node *type = createNode_V(TYPE, (yyvsp[-2].node), NULL); Node *nd = createNode_V(FILTER, type, (yyvsp[-1].node)); (yyval.node) = createNode_V(SELECTION, nd, (yyvsp[0].node)); }
#line 1376 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 30: /* arguments_opt: %empty  */
#line 177 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = NULL; }
#line 1382 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 31: /* arguments_opt: arguments  */
#line 178 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[0].node); }
#line 1388 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 32: /* arguments: BRAKET_OPEN_TOKEN argument_list BRAKET_CLOSE_TOKEN  */
#line 182 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[-1].node); }
#line 1394 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 33: /* argument_list: argument  */
#line 186 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(ARGUMENT, (yyvsp[0].node), NULL); }
#line 1400 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 34: /* argument_list: argument_list COMMA_TOKEN argument  */
#line 187 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(ARGUMENT, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1406 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 35: /* argument: name DOUBLE_DOT_TOKEN value  */
#line 191 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(NAME_DEFINITION, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1412 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 36: /* argument: name DOUBLE_DOT_TOKEN variable  */
#line 192 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(NAME_DEFINITION, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1418 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 37: /* argument: name LOWER_OPERATOR_TOKEN value  */
#line 193 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(LOWER_OPERATOR, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1424 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 38: /* argument: name GREATER_OPERATOR_TOKEN value  */
#line 194 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(GREATER_OPERATOR, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1430 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 39: /* argument: name GREATER_EQUAL_TOKEN value  */
#line 195 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(GREATER_EQUAL, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1436 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 40: /* argument: name LOWER_EQUAL_TOKEN value  */
#line 196 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(LOWER_EQUAL, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1442 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 41: /* argument: variable  */
#line 197 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(VARIABLE_DEFINITION, (yyvsp[0].node), NULL); }
#line 1448 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 42: /* argument: variable DOUBLE_DOT_TOKEN value  */
#line 198 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(VARIABLE_DEFINITION, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1454 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 43: /* value: rel_expr  */
#line 202 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(MATH_VALUE, (yyvsp[0].node), NULL); }
#line 1460 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 44: /* value: name  */
#line 203 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(VAR_VALUE, (yyvsp[0].node), NULL); }
#line 1466 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 45: /* value: string  */
#line 204 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(VALUE, (yyvsp[0].node), NULL); }
#line 1472 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 46: /* rel_expr: expr  */
#line 207 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[0].node); }
#line 1478 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 47: /* rel_expr: rel_expr LOWER_OPERATOR_TOKEN expr  */
#line 208 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(LOWER_EQUAL, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1484 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 48: /* rel_expr: rel_expr GREATER_OPERATOR_TOKEN expr  */
#line 209 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(GREATER_EQUAL, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1490 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 49: /* rel_expr: rel_expr LOWER_EQUAL_TOKEN expr  */
#line 210 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(LOWER_EQUAL, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1496 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 50: /* rel_expr: rel_expr GREATER_EQUAL_TOKEN expr  */
#line 211 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(GREATER_EQUAL, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1502 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 51: /* rel_expr: rel_expr EQUAL_OPERATOR_TOKEN expr  */
#line 212 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(EQUAL_OPERATOR, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1508 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 52: /* rel_expr: rel_expr NOT_EQUAL_TOKEN expr  */
#line 213 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(NOT_EQUAL, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1514 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 53: /* expr: mul_expr  */
#line 217 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[0].node); }
#line 1520 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 54: /* expr: expr PLUS_OPERATION_TOKEN mul_expr  */
#line 218 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(PLUS_OPERATION, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1526 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 55: /* expr: expr MINUS_OPERATION_TOKEN mul_expr  */
#line 219 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(MULTIPLY_OPERATION, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1532 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 56: /* mul_expr: atomic_expr  */
#line 223 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[0].node); }
#line 1538 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 57: /* mul_expr: mul_expr MULTIPLY_OPERATION_TOKEN atomic_expr  */
#line 224 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(MULTIPLY_OPERATION, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1544 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 58: /* mul_expr: mul_expr DIVIDE_OPERATION_TOKEN atomic_expr  */
#line 225 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_V(DIVIDE_OPERATION, (yyvsp[-2].node), (yyvsp[0].node)); }
#line 1550 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 59: /* atomic_expr: BRAKET_OPEN_TOKEN expr BRAKET_CLOSE_TOKEN  */
#line 229 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = (yyvsp[-1].node); }
#line 1556 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 60: /* atomic_expr: DOUBLE_TOKEN  */
#line 230 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_D(DOUBLE, (yyvsp[0].real), NULL, NULL); }
#line 1562 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 61: /* atomic_expr: INTEGER_TOKEN  */
#line 231 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                                                           { (yyval.node) = createNode_I(INTEGER, (yyvsp[0].integer), NULL, NULL); }
#line 1568 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 62: /* name: FIELD_TOKEN  */
#line 235 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                { (yyval.node) = createNode_S(FIELD, (yyvsp[0].string), NULL, NULL); }
#line 1574 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 63: /* variable: VARIABLE_TOKEN  */
#line 238 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                   { (yyval.node) = createNode_S(VARIABLE, (yyvsp[0].string), NULL, NULL); }
#line 1580 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;

  case 64: /* string: STRING_TOKEN  */
#line 241 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"
                 { (yyval.node) = createNode_S(STRING, (yyvsp[0].string), NULL, NULL); }
#line 1586 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"
    break;


#line 1590 "/home/asus/llp/test_llp/lab_3_llp/client/src/binary/graphql_parser.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 243 "/home/asus/llp/test_llp/lab_3_llp/client/src/parser/graphql.y"


void yyerror(const char *s) {
  (void) s;
//    fprintf(stderr, "error: %s\n", s);
}
