#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <float.h> // TO BE REMOVED




#define F  (1 << 14) 

/*Mask used to print the value in a user-friendly way*/
#define INTEGER_MASK 0x3ffff << 14
#define FRACTION_MASK 0x3fff 


/* Implementation of the 17.14 fixed-point representation.*/


typedef int32_t fixed_point;


inline fixed_point INT_TO_FIX (int value) 
{
	return value * F;
}

inline int FIX_TO_INT_R_ZERO (fixed_point value) 
{
	return value / F;
}  

inline int FIX_TO_INT_R_NEAR (fixed_point value) 
{
	if(value >= 0)
		return (value + F/2) / F;
	else
		return (value - F/2) / F;
}

inline fixed_point ADD_FIXED (fixed_point n1, fixed_point n2)
{
	return n1 + n2;
}

inline fixed_point ADD_FIXED_INT (fixed_point n1, int n2) 
{
	return n1 + (n2 * F);
} 

inline fixed_point SUB_FIXED (fixed_point n1, fixed_point n2)
{
	return n1 - n2;
}

inline fixed_point SUB_FIXED_INT (fixed_point n1, int n2) 
{
	return n1 - (n2 * F);
} 

inline fixed_point MUL_FIXED (fixed_point n1, fixed_point n2)
{
	return (((int64_t) n1) * n2) / F;
}

inline fixed_point MUL_FIXED_INT (fixed_point n1, int n2) 
{
	return n1 * n2;
} 

inline fixed_point DIV_FIXED (fixed_point n1, fixed_point n2)
{
	return (((int64_t) n1) * F )/ n2;
}

inline fixed_point DIV_FIXED_INT (fixed_point n1, int n2) 
{
	return n1 / n2;
} 


/* For testing */

void print_fixed_point(fixed_point value)
{
	int32_t int_part = (value & INTEGER_MASK) >> 14;
	int frac_part = (value & FRACTION_MASK);
	printf("INT: %d\n", int_part);
	double f = (float) frac_part / (float)F;
	printf("VAL: %f\n", int_part + f);
}


#endif