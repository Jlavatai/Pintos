#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define F  (1 << 14) 

/*Mask used to print the value in a user-friendly way*/
#define INTEGER_MASK 0x3ffff << 14
#define FRACTION_MASK 0x3fff 


/* Implementation of the 17.14 fixed-point representation.*/
typedef int32_t fixed_point;

extern inline fixed_point INT_TO_FIX (int value);
extern inline int FIX_TO_INT_R_ZERO (fixed_point value);
extern inline int FIX_TO_INT_R_NEAR (fixed_point value);
extern inline fixed_point ADD_FIXED (fixed_point n1, fixed_point n2);
extern inline fixed_point ADD_FIXED_INT (fixed_point n1, int n2);
extern inline fixed_point SUB_FIXED (fixed_point n1, fixed_point n2);
extern inline fixed_point SUB_FIXED_INT (fixed_point n1, int n2);
extern inline fixed_point MUL_FIXED (fixed_point n1, fixed_point n2);
extern inline fixed_point MUL_FIXED_INT (fixed_point n1, int n2);
extern inline fixed_point DIV_FIXED (fixed_point n1, fixed_point n2);
extern inline fixed_point DIV_FIXED_INT (fixed_point n1, int n2);

#endif