%{

%}

%start StmtList

%token TOK_TRANSFORM TOK_RULE TOK_LBRACE TOK_RBRACE TOK_SEMI TOK_ID
       TOK_TYPE TOK_OPTION TOK_STRING TOK_APPLY TOK_TARGETS TOK_RANGE
       TOK_LOAD
       TOK_IPv4 TOK_IPv6 TOK_MAC TOK_INT32 TOK_UINT32
       TOK_INT64 TOK_UINT64 TOK_OCTS TOK_NONE
       TOK_NUM TOK_DOTDOT

%%

StmtList:	StmtList Stmt | Empty ;

Stmt:		LoadStmt | TransformStmt | RuleStmt ;

LoadStmt:	TOK_LOAD TOK_STRING ;

TransformStmt:	TOK_TRANSFORM TOK_ID TOK_LBRACE TransformBody TOK_RBRACE ;

TransformBody:	TypeStmt
		| TypeStmt OptStmt
		| TypeStmt RangeStmt
		| TypeStmt RangeStmt OptStmt ;

TypeStmt:	TOK_TYPE Type TOK_SEMI ;

Type:		TOK_IPv4 | TOK_IPv6 | TOK_MAC | TOK_INT32 | TOK_UINT32
		| TOK_INT64 | TOK_UINT64 | TOK_OCTS | TOK_NONE ;

RangeStmt:	TOK_RANGE TOK_STRING TOK_SEMI ;

OptStmt:	TOK_OPTION TOK_STRING TOK_SEMI ;

RuleStmt:	TOK_RULE TOK_ID TOK_LBRACE RuleBody TOK_RBRACE ;

RuleBody:	ApplyStmt
		| ApplyStmt TargetsStmt ;

ApplyStmt:	TOK_APPLY TOK_ID TOK_SEMI ;

TargetsStmt:	TOK_TARGETS TOK_STRING TOK_SEMI ;

Empty:		;

%%
