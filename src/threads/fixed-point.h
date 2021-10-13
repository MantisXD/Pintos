#ifndef FIXED_POINT_H
#define FIXED_POINT_H
/*
 * Fixed-Point Real Arithmetic
 * use macros for performance
 *
 *         |sign||<--    int   -->||<--  frac  -->|
 *           32   31 30 ...  16 15  14 13 ...  2 1
 *     32bit  -   ----------------  --------------
 *
 */

typedef int real;

#define F (1<<14)

#define INT_TO_REAL(n) n*F
#define REAL_TO_INT(x) x/F
#define REAL_TO_INT_ROUND(x) ((x) >= 0 ? ((x)+((F)/2))/(F) : ((x)-((F)/2))/(F))

#define ADD_REAL(x,y) x+y
#define SUB_REAL(x,y) x-y
#define ADD_REAL_INT(x,n) x+n*F
#define SUB_REAL_INT(x,n) x-n*F

#define MUL_REAL(x,y) (((int64_t)x)*y/F)
#define MUL_REAL_INT(x,n) x*n
#define DIV_REAL(x,y) (((int64_t)x)*(F))/(y)
#define DIV_REAL_INT(x,n) x/n

#endif //FIXED_POINT_H
