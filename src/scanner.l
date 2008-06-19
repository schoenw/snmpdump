%{
#include "parser.h"
%}

%option   warn nodefault
%option   yylineno
%option	  noyywrap

ID       [a-zA-Z][a-zA-Z0-9\-]*

%%
"load"			{ return TOK_LOAD; }
"transform"		{ return TOK_TRANSFORM; }
"rule"			{ return TOK_RULE; }
"type"			{ return TOK_TYPE; }
"option"		{ return TOK_OPTION; }
"apply"			{ return TOK_APPLY; }
"targets"		{ return TOK_TARGETS; }
"\"".*"\""		{ return TOK_STRING; }

"ipv4"			{ return TOK_IPv4; }
"ipv6"			{ return TOK_IPv6; }
"mac"			{ return TOK_MAC; }
"int32"			{ return TOK_INT32; }
"uint32"		{ return TOK_UINT32; }
"int64"			{ return TOK_INT64; }
"uint64"	       	{ return TOK_UINT64; }
"octs"			{ return TOK_OCTS; }
"none"			{ return TOK_NONE; }
"{"		        { return TOK_LBRACE; }
"}"			{ return TOK_RBRACE; }
";"			{ return TOK_SEMI; }
".."			{ return TOK_DOTDOT; }
[0-9]+			{ return TOK_NUM; }
{ID}			{ return TOK_ID; }
"#".*"\n"
[ \t\r\n]*		{}

%%
