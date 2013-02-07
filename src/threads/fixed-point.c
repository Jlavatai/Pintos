#include "threads/fixed-point.h"

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