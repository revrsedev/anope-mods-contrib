/* ----------------------------------------------------------------------------
 * Name    : diceserv.cpp
 * Author  : Naram Qashat (CyberBotX)
 * Version : 3.0.4
 * Date    : (Last modified) August 26, 2017
 * ----------------------------------------------------------------------------
 * The following applies to the non-Anope-derived portions of the code
 * (excluding the RNG):

The MIT License (MIT)

Copyright (c) 2004-2017 Naram Qashat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

 * (This basically covers the core functionality of DiceServ.)
 *
 * The following applies to the Anope-derived portions of the code:
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 1, or (at your option) any later
 * version.
 * ----------------------------------------------------------------------------
 * Requires: Anope 2.0.x
 * ----------------------------------------------------------------------------
 * Description:
 *
 * A dice rolling pseudo-client, mainly useful for playing pen & paper RPGs,
 * such as Dungeons and Dragons, over IRC.
 * ----------------------------------------------------------------------------
 * Configuration example can be found in diceserv.example.conf.
 * ----------------------------------------------------------------------------
 * Changelog:
 *
 * 3.0.4 - Replaced Agner Fog's SFMT+MOA RNG with a dSFMT RNG by the authors
 *           of the Mersenne Twister RNG, mainly due to concerns over the RNG
 *           not producing unbiased results.
 * 3.0.3 - Fixed an issue with user access in a moderated channel.
 *       - Removed unused delimiter argument from my Join() function.
 *       - Fixed an issue with DiceServData's HasExtended() function so it
 *           would properly detect if we have extended results or not.
 *       - Changed logic on determining when to start attempting to get
 *           extended output.
 *       - Fixed some typos and comments.
 * 3.0.2 - Fixed an issue with SET IGNORE's reloading.
 *       - Better handling on determining when to use extended output.
 *       - Replaced usage of OnPostCommand for adding to NickServ/ChanServ
 *           info, used OnNickInfo and OnChanInfo instead.
 *       - Better checks for numbers in Infix to Postfix conversion.
 *       - Prevent factorials of 13 or higher due to limit on 32-bit integers
 *           as well as execution time.
 *       - Prevent potential crashes if a fantasy command other than the D&D
 *           3e Character one is used with no arguments.
 *       - Minor C++11 fixes.
 *       - Other minor code cleanups.
 * 3.0.1 - Fixed issues with loading an old DiceServ database so it actually
 *           works (there was a typo in the configuration file plus a timer
 *           has to be used).
 *       - Made a specialization of stringify for double to correct issues
 *           with some numbers using scientific notation when they shouldn't
 *           have as well as bring the precision back up.
 *       - Fixed EARTHDAWN on *nix-based systems.
 *       - Fixed DND3ECHAR so it actually works.
 * 3.0.0 - Massive rewrite, now only targets Anope 2.0.x and has been heavily
 *           modularized.
 *       - Added support for functions to have an arbitrary number of
 *           arguments, used by only the max and min function currently.
 *       - Better handling of when to switch from long-form extended output to
 *           short-form extended output to no extended output.
 *       - Made sure that the math functions that were added for use with
 *           Visual Studio are only compiled in for Visual Studio 2012 or
 *           earlier, as they were finally included with Visual Studio 2013.
 *       - Completely restructured how results are handled.
 *       - Removed dtoa function as Anope's stringify could be used to replace
 *           it (at the cost of lower output precision on floating-point
 *           values).
 *       - Replaced the Mersenne Twister RNG with a combination RNG of a
 *           SIMD-oriented Fast Mersenne Twister RNG and a Mother-of-all RNG.
 *       - Added atan2 math function.
 * 2.0.3 - Fix some memory leaks that went unnoticed by me until recently.
 * 2.0.2 - Fix a crash bug for the Anope 1.8.x versions and a lack of an error
 *           message for the Anope 1.9.x versions caused if there is nothing
 *           before or after the tilde.
 * 2.0.1 - Minor fix of permission in DiceServ's SET command.
 *       - Minor edit of GECOS of DiceServ to use "Service" instead of
 *           "Server".
 *       - Added version for Anope 1.9.5.
 *   2.0 - Replaced Coda's expression parser with a parser of my own that
 *           converts the expression from infix to postfix using the
 *           shunting-yard algorithm and then evaluates it.
 *       - Added support for DnD3e character creation rolls.
 *       - Removed Exalted dice rolls from the service, I'm not 100% sure they
 *           were ever being done right.
 *       - Used enums for the dice roll types and errors for easier usage.
 *       - Fixed overflow checks.
 *       - Allow for d% anywhere in an expression, suggested by Namegduf.
 *       - Split apart parsing the expression and evaluating it, suggested by
 *           Namegduf.
 *       - Better buffer overflow checking, and removed check for the
 *           expression being too long, the current parser can handle long
 *           expressions unlike the last parser (no offense to Coda).
 *       - Added support for the pen & paper RPG Earthdawn, suggested by
 *           DukePyrolator.
 *       - Added support for math functions. (such as sqrt, trunc, cos, etc.)
 *       - Added support for the math constants of e and pi.
 *       - Added a CALC command which is like ROLL but without rounding.
 *       - Added configuration options for DiceServ's pseudo-client name as
 *           well as giving a network-wide ability for channel operators to
 *           set DiceServ channel ignores.
 *       - Added functionality for a shorter extended output if showing the
 *           results of each individual roll would be too long to display.
 *       - Better way of determining when to display the extended output
 *           buffer.
 *       - Utilize the Mersenne Twister RNG (random number generator) instead
 *           of Anope's RNG, it's faster but uses up a bit more memory. As a
 *           result, Coda's algorithm used in the dice roller is not longer
 *           used.
 *       - Added support for dual-argument functions of max(), min, and rand().
 *   1.0 - Initial version (was only part of an Epona 1.4.14 edit).
 *       - Contained expression parser and dice roller algorithms from Adam
 *           Higerd (Coda Highland).
 *
 * ----------------------------------------------------------------------------
 */

/* RequiredLibraries: m */

#include <algorithm>
#include <functional>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <stack>
#include "diceserv.h"
#ifdef _MSC_VER
# include <float.h>
#endif
#include <emmintrin.h>

static const int DICE_MAX_TIMES = 25;
static const unsigned DICE_MAX_DICE = 99999;
static const unsigned DICE_MAX_SIDES = 99999;

/** Determine if the double-precision floating point value is infinite or not.
 * @param num The double-precision floating point value to check
 * @return true if the value is infinite, false otherwise
 */
static inline bool is_infinite(double num)
{
#ifdef _MSC_VER
	int fpc = _fpclass(num);
	return fpc == _FPCLASS_NINF || fpc == _FPCLASS_PINF;
#else
	return std::isinf(num);
#endif
}

/** Determine if the double-precision floating point value is NaN (Not a Number) or not.
 * @param num The double-precision floating point value to check
 * @return true if the value is NaN, false otherwise
 */
static inline bool is_notanumber(double num)
{
#ifdef _MSC_VER
	int fpc = _fpclass(num);
	return fpc == _FPCLASS_SNAN || fpc == _FPCLASS_QNAN;
#else
	return std::isnan(num);
#endif
}

#if defined(_MSC_VER) && _MSC_VER < 1800
/** Calculate inverse hyperbolic cosine for Windows (only needed when compiling with Visual Studio 2012 or earlier).
 * @param num The double-precision floating point value to calculate
 * @return The inverse hyperbolic cosine of the value
 */
static inline double acosh(double num)
{
	return std::log(num + std::sqrt(num - 1) * std::sqrt(num + 1));
}

/** Calculate inverse hyperbolic sine for Windows (only needed when compiling with Visual Studio 2012 or earlier).
 * @param num The double-precision floating point value to calculate
 * @return The inverse hyperbolic sine of the value
 */
static inline double asinh(double num)
{
	return std::log(num + std::sqrt(num * num + 1));
}

/** Calculate inverse hyperbolic tangent for Windows (only needed when compiling with Visual Studio 2012 or earlier).
 * @param num The double-precision floating point value to calculate
 * @return The inverse hyperbolic tangent of the value
 */
static inline double atanh(double num)
{
	return 0.5 * std::log((1 + num) / (1 - num));
}

/** Calculate cube root for Windows (only needed when compiling with Visual Studio 2012 or earlier).
 * @param num The double-precision floating point value to calculate
 * @return The cube root of the value
 */
static inline double cbrt(double num)
{
	return std::pow(num, 1.0 / 3.0);
}
#endif

/** A double-precision SIMD-oriented Fast Mersenne Twister RNG.
 *
 * This class was copied from Mutsuo Saito and Makoto Matsumoto,
 * obtained from http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/SFMT/
 * Modified by Naram Qashat to only include what was needed by DiceServ,
 * as well as containing everything within the class.
 *
 * The following license applies to this class:
Copyright (c) 2007, 2008, 2009 Mutsuo Saito, Makoto Matsumoto
and Hiroshima University.
Copyright (c) 2011, 2002 Mutsuo Saito, Makoto Matsumoto, Hiroshima
University and The University of Tokyo.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of the Hiroshima University nor the names of
      its contributors may be used to endorse or promote products
      derived from this software without specific prior written
      permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
class dSFMT216091
{
	union w128_t
	{
		__m128i si;
		uint64_t u[2];
		uint32_t u32[4];
		double d[2];
	};
	union X128I_T
	{
		uint64_t u[2];
		__m128i i128;
	};

	static const int DSFMT_POS1 = 1890; // The pick up position of the array
	static const int DSFMT_SL1 = 23; // The parameter of shift left as four 32-bit registers
	// A bitmask, used in the recursion. These parameters are introduced to break symmetry of SIMD
	static const uint64_t DSFMT_MSK1 = 0x000bf7df7fefcfffULL;
	static const uint64_t DSFMT_MSK2 = 0x000e7ffffef737ffULL;
	// These definitions are part of a 128-bit period certification vector
	static const uint64_t DSFMT_FIX1 = 0xd7f95a04764c27d7ULL;
	static const uint64_t DSFMT_FIX2 = 0x6a483861810bebc2ULL;
	static const uint64_t DSFMT_PCV1 = 0x3af0a8f3d5600000ULL;
	static const uint64_t DSFMT_PCV2 = 0x0000000000000001ULL;

	static const uint64_t DSFMT_LOW_MASK = 0x000FFFFFFFFFFFFFULL;
	static const uint64_t DSFMT_HIGH_CONST = 0x3FF0000000000000ULL;
	static const int DSFMT_SR = 12;

	static const int SSE2_SHUFF = 0x1b;

	static const int DSFMT_MEXP = 216091; // Mersenne Exponent. The period of the sequence is a multiple of 2^DSFMT_MEXP - 1.
	static const int DSFMT_N = (DSFMT_MEXP - 128) / 104 + 1; // DSFMT generator has an internal state array of 128-bit integers, and N is its size
	static const int DSFMT_N64 = DSFMT_N * 2; // N64 is the size of internal state array when regarded as an array of 64-bit integers

	static const X128I_T sse2_param_mask;

	w128_t status[DSFMT_N + 1]; // The 128-bit internal state array
	int idx;

	/** Represents the recursion formula.
	 * @param r output 128-bit
	 * @param a a 128-bit part of the internal state array
	 * @param b a 128-bit part of the internal state array
	 * @param u a 128-bit part of the internal state array (I/O)
	 */
	static void do_recursion(w128_t &r, const w128_t &a, const w128_t &b, w128_t &u)
	{
		__m128i x = a.si;
		__m128i z = _mm_slli_epi64(x, DSFMT_SL1);
		__m128i y = _mm_shuffle_epi32(u.si, SSE2_SHUFF);
		z = _mm_xor_si128(z, b.si);
		y = _mm_xor_si128(y, z);

		__m128i v = _mm_srli_epi64(y, DSFMT_SR);
		__m128i w = _mm_and_si128(y, sse2_param_mask.i128);
		v = _mm_xor_si128(v, x);
		v = _mm_xor_si128(v, w);
		r.si = v;
		u.si = y;
	}

	/** Fills the internal state array with double precision floating point pseudorandom numbers of the IEEE 754 format.
	 */
	void gen_rand_all()
	{
		w128_t lung = this->status[DSFMT_N];
		do_recursion(this->status[0], this->status[0], this->status[DSFMT_POS1], lung);
		int i;
		for (i = 1; i < DSFMT_N - DSFMT_POS1; ++i)
			do_recursion(this->status[i], this->status[i], this->status[i + DSFMT_POS1], lung);
		for (; i < DSFMT_N; ++i)
			do_recursion(this->status[i], this->status[i], this->status[i + DSFMT_POS1 - DSFMT_N], lung);
		this->status[DSFMT_N] = lung;
	}

	/** Initializes the internal state array with a 32-bit integer seed.
	 * @param seed a 32-bit integer used as the seed.
	 */
	void init_gen_rand(uint32_t seed)
	{
		uint32_t *psfmt = &this->status[0].u32[0];
		psfmt[0] = seed;
		for (int i = 1; i < (DSFMT_N + 1) * 4; ++i)
			psfmt[i] = 1812433253UL * (psfmt[i - 1] ^ (psfmt[i - 1] >> 30)) + i;
		this->initial_mask();
		this->period_certification();
		this->idx = DSFMT_N64;
	}

	/** Initializes the internal state array to fit the IEEE 754 format.
	 */
	void initial_mask()
	{
		uint64_t *psfmt = &this->status[0].u[0];
		for (int i = 0; i < DSFMT_N * 2; ++i)
			psfmt[i] = (psfmt[i] & DSFMT_LOW_MASK) | DSFMT_HIGH_CONST;
	}

	/** Certificate the period of 2^DSFMT_MEXP - 1.
	 */
	void period_certification()
	{
		static const uint64_t pcv[] = { DSFMT_PCV1, DSFMT_PCV2 };
		uint64_t tmp[] = { this->status[DSFMT_N].u[0] ^ DSFMT_FIX1, this->status[DSFMT_N].u[1] ^ DSFMT_FIX2 };

		uint64_t inner = tmp[0] & pcv[0];
		inner ^= tmp[1] & pcv[1];
		int i;
		for (i = 32; i > 0; i >>= 1)
			inner ^= inner >> i;
		inner &= 1;
		// check OK
		if (inner == 1)
			return;
		// check NG, and modification
		if ((DSFMT_PCV2 & 1) == 1)
			this->status[DSFMT_N].u[1] ^= 1;
		else
		{
			for (i = 1; i >= 0; --i)
			{
				uint64_t work = 1;
				for (int j = 0; j < 64; ++j)
				{
					if (work & pcv[i])
					{
						this->status[DSFMT_N].u[i] ^= work;
						return;
					}
					work <<= 1;
				}
			}
		}
	}

	/** Generates and returns double precision pseudorandom number which distributes uniformly in the range [1, 2).
	 * @return double precision floating point pseudorandom number
	 *
	 * This is the primitive and faster than generating numbers in other ranges.
	 */
	double genrand_close1_open2()
	{
		double *psfmt64 = &this->status[0].d[0];

		if (this->idx >= DSFMT_N64)
		{
			this->gen_rand_all();
			this->idx = 0;
		}
		return psfmt64[this->idx++];
	}

	/** Generates and returns double precision pseudorandom number which distributes uniformly in the range [0, 1).
	 * @return double precision floating point pseudorandom number
	 */
	double genrand_close_open()
	{
		return this->genrand_close1_open2() - 1.0;
	}

public:
	dSFMT216091(uint32_t seed)
	{
		this->init_gen_rand(seed);
	}

	/** Generate a random integer within the given range.
	 * @param min The minimum value of the range
	 * @param max The maximum value of the range
	 * @return An integer in the interval min <= x <= max
	 *
	 * This function was not part of the original dSFMT implementation and was added by Naram Qashat.
	 */
	int Random(int min, int max)
	{
		return static_cast<int>(std::floor(this->genrand_close_open() * (max - min + 1)) + min);
	}
};

const dSFMT216091::X128I_T dSFMT216091::sse2_param_mask = { { DSFMT_MSK1, DSFMT_MSK2 } };

static dSFMT216091 sfmtRNG(static_cast<uint32_t>(std::time(NULL)));

/** Determine if the given character is a number.
 * @param chr Character to check
 * @return true if the character is a number, false otherwise
 */
static inline bool is_number(char chr)
{
	return (chr >= '0' && chr <= '9') || chr == '.';
}

/** Determine if the given string is a number.
 * @param str String to check
 * @return true if the string is a number, false otherwise
 */
static inline bool is_number_str(const Anope::string &str)
{
	Anope::string::const_iterator begin = str.begin(), end = str.end();
	return std::all_of(begin, end, [](char chr) { return is_number(chr); }) && std::count(begin, end, '.') < 2;
}

/** Determine if the given character is a multiplication or division operator.
 * @param chr Character to check
 * @return true if the character is a multiplication or division operator, false otherwise
 */
static inline bool is_muldiv(char chr)
{
	return chr == '%' || chr == '/' || chr == '*';
}

/** Determine if the given character is an addition or subtraction operator.
 * @param chr Character to check
 * @return true if the character is an addition or subtraction operator, false otherwise
 */
static inline bool is_plusmin(char chr)
{
	return chr == '+' || chr == '-';
}

/** Determine if the given character is an operator of any sort, except for parentheses.
 * @param chr Character to check
 * @return true if the character is a non-parenthesis operator, false otherwise
 */
static inline bool is_op_noparen(char chr)
{
	return is_plusmin(chr) || is_muldiv(chr) || chr == '^' || chr == 'd';
}

/** Determine if the given character is an operator of any sort.
 * @param chr Character to check
 * @return true if the character is an operator, false otherwise
 */
static inline bool is_operator(char chr)
{
	return chr == '(' || chr == ')' || is_op_noparen(chr);
}

/** Determine if the substring portion of the given string is a function.
 * @param str String to check
 * @param pos Starting position of the substring to check, defaults to 0
 * @return 0 if the string isn't a function, or a number corresponding to the length of the function name
 */
static inline unsigned is_function(const Anope::string &str, unsigned pos = 0)
{
	// We only need a 5 character substring as that's the largest substring we will be looking at
	Anope::string func = str.substr(pos, 5);
	// acosh, asinh, atan2, atanh, floor, log10, round, trunc
	Anope::string func_5 = func.substr(0, 5);
	if (func_5.equals_ci("acosh") || func_5.equals_ci("asinh") || func_5.equals_ci("atan2") || func_5.equals_ci("atanh") || func_5.equals_ci("floor") ||
		func_5.equals_ci("log10") || func_5.equals_ci("round") || func_5.equals_ci("trunc"))
		return 5;
	// acos, asin, atan, cbrt, ceil, cosh, rand, sinh, sqrt, tanh
	Anope::string func_4 = func.substr(0, 4);
	if (func_4.equals_ci("acos") || func_4.equals_ci("asin") || func_4.equals_ci("atan") || func_4.equals_ci("cbrt") || func_4.equals_ci("ceil") ||
		func_4.equals_ci("cosh") || func_4.equals_ci("rand") || func_4.equals_ci("sinh") || func_4.equals_ci("sqrt") || func_4.equals_ci("tanh"))
		return 4;
	// abs, cos, deg, exp, fac, log, max, min, rad, sin, tan
	Anope::string func_3 = func.substr(0, 3);
	if (func_3.equals_ci("abs") || func_3.equals_ci("cos") || func_3.equals_ci("deg") || func_3.equals_ci("exp") || func_3.equals_ci("fac") ||
		func_3.equals_ci("log") || func_3.equals_ci("max") || func_3.equals_ci("min") || func_3.equals_ci("rad") || func_3.equals_ci("sin") ||
		func_3.equals_ci("tan"))
		return 3;
	// None of the above
	return 0;
}

/** Determine the number of arguments that the given function needs.
 * @param str Function string to check
 * @return Returns 1 except for the min and max functions which return -2 (to say they require AT LEAST 2 arguments), and the atan2 and rand functions which return 2
 */
static inline int function_argument_count(const Anope::string &str)
{
	Anope::string func_3 = str.substr(0, 3);
	if (func_3.equals_ci("max") || func_3.equals_ci("min"))
		return -2;
	if (str.equals_ci("atan2") || str.equals_ci("rand"))
		return 2;
	return 1;
}

/** Determine if the substring portion of the given string is a constant (currently only e and pi).
 * @param str String to check
 * @param pos Starting position of the substring to check, defaults to 0
 * @return 0 if the string isn't a constant, or a number corresponding to the length of the constant's name
 */
static inline unsigned is_constant(const Anope::string &str, unsigned pos = 0)
{
	// We only need a 2 character substring as that's the largest substring we will be looking at
	Anope::string constant = str.substr(pos, 2);
	// pi
	if (constant.substr(0, 2).equals_ci("pi"))
		return 2;
	// e
	if (constant.substr(0, 1).equals_ci("e"))
		return 1;
	// None of the above
	return 0;
}

/** Determine if the given operator has a higher precedence than the operator on the top of the stack during infix to postfix conversion.
 * @param adding The operator we are adding to the stack, or an empty string if nothing is being added and we just want to remove
 * @param topstack The operator that was at the top of the operator stack
 * @return 0 if the given operator has the same or lower precedence (and won't cause a pop), 1 if the operator has higher precedence (and will cause a pop)
 *
 * In addition to the above in regards to the return value, there are other situations. If the top of the stack is an open parenthesis,
 * or is empty, a 0 will be returned to stop the stack from popping anything else. If nothing is being added to the stack and the previous
 * situation hasn't occurred, a 1 will be returned to signify to continue popping the stack until the previous situation occurs. If the operator
 * being added is a function, we return 0 to signify we aren't popping. If the top of the stack is a function, we return 1 to signify we are
 * popping. A -1 is only returned if an invalid operator is given, hopefully that will never happen.
 */
static inline int would_pop(const Anope::string &adding, const Anope::string &topstack)
{
	if (adding.empty())
		return topstack.empty() || topstack == "(" ? 0 : 1;
	if (is_function(adding))
		return 0;
	if (topstack.empty() || topstack == "(")
		return 0;
	if (is_function(topstack))
		return 1;
	if (topstack == adding && adding != "^")
		return 1;
	switch (adding[0])
	{
		case 'd':
			return 0;
		case '^':
			return topstack.equals_ci("d") ? 1 : 0;
		case '%':
		case '/':
		case '*':
			return topstack == "^" || topstack.equals_ci("d") || is_muldiv(topstack[0]) ? 1 : 0;
		case '+':
		case '-':
			return is_op_noparen(topstack[0]) ? 1 : 0;
	}
	return -1;
}

/** Calculate a die roll for the given number of sides for a set number of times.
 * @param num Number of times to throw the die
 * @param sides Number of sides on the die
 * @return The results of the dice in a special structure
 */
DiceResult Dice(int num, unsigned sides)
{
	DiceResult result = DiceResult(num, sides);
	for (int i = 0; i < num; ++i)
		// Get a random number between 1 and the number of sides
		result.AddResult(sfmtRNG.Random(1, sides));
	return result;
}

/** Round a value to the given number of decimals, originally needed for Windows but also used for other OSes as well due to undefined references.
 * @param val The value to round
 * @param decimals The number of digits after the decimal point, defaults to 0
 * @return The rounded value
 *
 * NOTE: Function is a slightly modified form of the code from this page:
 * http://social.msdn.microsoft.com/forums/en-US/vclanguage/thread/a7d4bf31-6c32-4b25-bc76-21b29f5287a1/
 */
static double my_round(double val, unsigned decimals = 0)
{
	if (!val) // val must be different from zero to avoid division by zero!
		return 0;
	double sign = std::abs(val) / val; // we obtain the sign to calculate positive always
	double tempval = std::abs(val * std::pow(10.0, static_cast<double>(decimals))); // shift decimal places
	unsigned tempint = static_cast<unsigned>(tempval);
	double decimalpart = tempval - tempint; // obtain just the decimal part
	if (decimalpart >= 0.5)
		tempval = std::ceil(tempval); // next integer number if greater or equal to 0.5
	else
		tempval = std::floor(tempval); // otherwise stay in the current integer part
	return (tempval * std::pow(10.0, -static_cast<int>(decimals))) * sign; // shift again to the normal decimal places
}

/** Structure to store the infix notation string as well as the positions each character is compared to the original input */
struct Infix
{
	Anope::string str;
	std::vector<unsigned> positions;

	Infix(const Anope::string &newStr, std::vector<unsigned> newPositions)
	{
		this->str = newStr;
		this->positions = newPositions;
	}

	Infix(const Anope::string &newStr, unsigned newPositions[], unsigned num)
	{
		this->str = newStr;
		this->positions = std::vector<unsigned>(newPositions, newPositions + num);
	}
};

/** Fix an infix notation equation.
 * @param infix The original infix notation equation
 * @return A fixed infix notation equation
 *
 * This will convert a single % to 1d100, place a 1 in front of any d's that have no numbers before them, change all %'s after a d into 100,
 * add *'s for implicit multiplication, and convert unary -'s to _ for easier parsing later.
 */
static Infix FixInfix(const Anope::string &infix)
{
	if (infix == "%")
	{
		unsigned tmp[] = { 0, 0, 0, 0, 0 };
		return Infix("1d100", tmp, 5);
	}
	bool prev_was_func = false, prev_was_const = false;
	Anope::string newinfix;
	std::vector<unsigned> positions;
	unsigned len = infix.length();
	for (unsigned x = 0; x < len; ++x)
	{
		// Check for a function, and skip it if it exists
		unsigned func = is_function(infix, x);
		if (func)
		{
			if (x && is_number(infix[x - 1]))
			{
				newinfix += '*';
				positions.push_back(x);
			}
			newinfix += infix.substr(x, func);
			for (unsigned y = 0; y < func; ++y)
				positions.push_back(x + y);
			x += func - 1;
			prev_was_func = true;
			continue;
		}
		// Check for a constant, and skip it if it exists
		unsigned constant = is_constant(infix, x);
		if (constant)
		{
			if (x && is_number(infix[x - 1]))
			{
				newinfix += '*';
				positions.push_back(x);
			}
			newinfix += infix.substr(x, constant);
			for (unsigned y = 0; y < constant; ++y)
				positions.push_back(x + y);
			if (x + constant < len && (is_number(infix[x + constant]) || is_constant(infix, x + constant) || is_function(infix, x + constant)))
			{
				newinfix += '*';
				positions.push_back(x + constant);
			}
			x += constant - 1;
			prev_was_const = true;
			continue;
		}
		char curr = static_cast<char>(std::tolower(infix[x]));
		if (curr == 'd')
		{
			positions.push_back(x);
			if (!x)
			{
				newinfix += "1d";
				positions.push_back(x);
			}
			else
			{
				if (!is_number(infix[x - 1]) && infix[x - 1] != ')' && !prev_was_const)
				{
					newinfix += '1';
					positions.push_back(x);
				}
				newinfix += 'd';
			}
			if (x != len - 1 && infix[x + 1] == '%')
			{
				newinfix += "100";
				++x;
				positions.push_back(x);
				positions.push_back(x);
			}
		}
		else if (curr == '(')
		{
			if (x && !prev_was_func && (is_number(infix[x - 1]) || prev_was_const))
			{
				newinfix += '*';
				positions.push_back(x);
			}
			newinfix += '(';
			positions.push_back(x);
		}
		else if (curr == ')')
		{
			newinfix += ')';
			positions.push_back(x);
			if (x != len - 1 && (is_number(infix[x + 1]) || infix[x + 1] == '(' || is_constant(infix, x + 1)))
			{
				newinfix += '*';
				positions.push_back(x);
			}
		}
		else if (curr == '-')
		{
			positions.push_back(x);
			if (x != len - 1 && (!x ? 1 : is_op_noparen(static_cast<char>(std::tolower(infix[x - 1]))) || infix[x - 1] == '(' || infix[x - 1] == ','))
			{
				if (infix[x + 1] == '(' || is_function(infix, x + 1))
				{
					newinfix += "0-";
					positions.push_back(x);
				}
				else if (is_number(infix[x + 1]) || is_constant(infix, x + 1))
					newinfix += '_';
				else
					newinfix += '-';
			}
			else
				newinfix += '-';
		}
		else
		{
			newinfix += curr;
			positions.push_back(x);
		}
		prev_was_func = prev_was_const = false;
	}
	positions.push_back(len);
	return Infix(newinfix, positions);
}

/** Validate an infix notation equation.
 * @param infix The infix notation equation to validate
 * @return false for an invalid equation, true for a valid one
 *
 * The validation is as follows:
 * - All functions must have an open parenthesis after them.
 * - A comma must be prefixed by a number or close parenthesis and must be suffixed by a number, open parenthesis, _ for unary minus, constant, or function.
 * - All non-parenthesis operators must be prefixed by a number or close parenthesis and suffixed by a number, open parenthesis, _ for unary minus, constant, or function.
 * - All open parentheses must be prefixed by an operator, open parenthesis, or comma and suffixed by a number, an open parenthesis, _ for unary minus, constant, or function.
 * - All close parentheses must be prefixed by a number or close parenthesis and suffixed by an operator, close parenthesis, or comma.
 */
static bool CheckInfix(DiceServData &data, const Infix &infix)
{
	bool prev_was_func = false, prev_was_const = false;
	for (unsigned x = 0, len = infix.str.length(); x < len; ++x)
	{
		unsigned position = infix.positions[x];
		// Check for a function, and skip it if it exists
		unsigned func = is_function(infix.str, x);
		if (func)
		{
			if ((x + func < len && infix.str[x + func] != '(') || x + func >= len)
			{
				data.errPos = infix.positions[x + func >= len ? len : x + func];
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("That looks like a function, but it's missing an opening '(' after the name.");
				return false;
			}
			x += func - 1;
			prev_was_func = true;
			continue;
		}
		// Check for a constant, and skip it if it exists
		unsigned constant = is_constant(infix.str, x);
		if (constant)
		{
			x += constant - 1;
			prev_was_const = true;
			continue;
		}
		if (infix.str[x] == ',')
		{
			if (!x ? 1 : !is_number(infix.str[x - 1]) && infix.str[x - 1] != ')' && !prev_was_const)
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("A comma must come after a number or ')'.");
				return false;
			}
			if (x == len - 1 ? 1 : !is_number(infix.str[x + 1]) && infix.str[x + 1] != '(' && infix.str[x + 1] != '_' && !is_constant(infix.str, x + 1) &&
				!is_function(infix.str, x + 1))
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("A comma must be followed by a number or '('.");
				return false;
			}
		}
		else if (is_op_noparen(infix.str[x]))
		{
			if (!x ? 1 : !is_number(infix.str[x - 1]) && infix.str[x - 1] != ')' && !prev_was_const)
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("An operator must come after a number or ')'.");
				return false;
			}
			if (x == len - 1 ? 1 : !is_number(infix.str[x + 1]) && infix.str[x + 1] != '(' && infix.str[x + 1] != '_' && !is_constant(infix.str, x + 1) &&
				!is_function(infix.str, x + 1))
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("An operator must be followed by a number or '('.");
				return false;
			}
		}
		else if (infix.str[x] == '(')
		{
			if (x && !is_op_noparen(infix.str[x - 1]) && infix.str[x - 1] != '(' && infix.str[x - 1] != ',' && !prev_was_func)
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("It looks like there's a missing operator before '('.");
				return false;
			}
			if (x != len - 1 && !is_number(infix.str[x + 1]) && infix.str[x + 1] != '(' && infix.str[x + 1] != '_' && !is_constant(infix.str, x + 1) &&
				!is_function(infix.str, x + 1))
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("Expected a number (or another '(') right after '('.");
				return false;
			}
		}
		else if (infix.str[x] == ')')
		{
			if (x && !is_number(infix.str[x - 1]) && infix.str[x - 1] != ')' && !prev_was_const)
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("Expected a number (or ')') right before ')'.");
				return false;
			}
			if (x != len - 1 && !is_op_noparen(infix.str[x + 1]) && infix.str[x + 1] != ')' && infix.str[x + 1] != ',')
			{
				data.errPos = position;
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("Expected an operator, ',' or ')' after ')'.");
				return false;
			}
		}
		else if (!is_number(infix.str[x]) && !is_muldiv(infix.str[x]) && !is_plusmin(infix.str[x]) && !is_operator(infix.str[x]) && infix.str[x] != '_')
		{
			data.errPos = position;
			data.errCode = DICE_ERROR_PARSE;
			data.errStr = _("That expression contains an invalid character.");
			return false;
		}
		prev_was_func = prev_was_const = false;
	}
	return true;
}

/** Tokenize an infix notation equation by adding spaces between operators.
 * @param infix The original infix notation equation to tokenize
 * @return A new infix notation equation with spaces between operators
 */
static Infix TokenizeInfix(const Infix &infix)
{
	Anope::string newinfix;
	std::vector<unsigned> positions;
	for (unsigned x = 0, len = infix.str.length(); x < len; ++x)
	{
		unsigned position = infix.positions[x], func = is_function(infix.str, x), constant = is_constant(infix.str, x);
		char curr = infix.str[x];
		if (func)
		{
			if (x && !newinfix.empty() && newinfix[newinfix.length() - 1] != ' ')
			{
				newinfix += ' ';
				positions.push_back(position);
			}
			newinfix += infix.str.substr(x, func);
			for (unsigned y = 0; y < func; ++y)
				positions.push_back(infix.positions[x + y]);
			if (x != len - 1)
			{
				newinfix += ' ';
				positions.push_back(infix.positions[x + func]);
			}
			x += func - 1;
		}
		else if (constant)
		{
			if (x && !newinfix.empty() && newinfix[newinfix.length() - 1] != ' ' && newinfix[newinfix.length() - 1] != '_')
			{
				newinfix += ' ';
				positions.push_back(position);
			}
			newinfix += infix.str.substr(x, constant);
			for (unsigned y = 0; y < constant; ++y)
				positions.push_back(infix.positions[x + y]);
			if (x != len - 1)
			{
				newinfix += ' ';
				positions.push_back(infix.positions[x + constant]);
			}
			x += constant - 1;
		}
		else if (curr == ',')
		{
			if (x && !newinfix.empty() && newinfix[newinfix.length() - 1] != ' ')
			{
				newinfix += ' ';
				positions.push_back(position);
			}
			newinfix += ',';
			positions.push_back(position);
			if (x != len - 1)
			{
				newinfix += ' ';
				positions.push_back(position);
			}
		}
		else if (is_operator(curr))
		{
			if (x && !newinfix.empty() && newinfix[newinfix.length() - 1] != ' ')
			{
				newinfix += ' ';
				positions.push_back(position);
			}
			newinfix += curr;
			positions.push_back(position);
			if (x != len - 1)
			{
				newinfix += ' ';
				positions.push_back(position);
			}
		}
		else
		{
			newinfix += curr;
			positions.push_back(position);
		}
	}
	return Infix(newinfix, positions);
}

/** Enumeration for PostfixValue to determine its type */
enum PostfixValueType
{
	POSTFIX_VALUE_NONE,
	POSTFIX_VALUE_DOUBLE,
	POSTFIX_VALUE_STRING
};

/** Base class for values in a postfix equation */
class PostfixValueBase
{
	/** The type for the value */
	PostfixValueType type;

protected:
	/** When overridden, will be used to delete memory allocated.
	 */
	virtual void Clear() = 0;

public:
	/** Constructor that take the type for the value.
	 */
	PostfixValueBase(PostfixValueType t) : type(t)
	{
	}

	/** Destructor, virtual so that derived classes can call the Clear function.
	 */
	virtual ~PostfixValueBase()
	{
	}

	/** Gets the type of the value.
	 * @return The value's type
	 */
	PostfixValueType Type() const
	{
		return this->type;
	}

	/** Creates a clone of the value.
	 * @return A clone of the value
	 */
	virtual PostfixValueBase *Clone() const = 0;
};

/** Version of PostfixValue for double (this is used for numbers) */
class PostfixValueDouble : public PostfixValueBase
{
	/** The value */
	double *val;

protected:
	/** Deletes the value to prevent memory leaks.
	 */
	void Clear()
	{
		delete this->val;
	}

public:
	/** Constructor that takes the value to store.
	 */
	PostfixValueDouble(double Val) : PostfixValueBase(POSTFIX_VALUE_DOUBLE), val(new double(Val))
	{
	}

	/** Copy constructor, duplicates the value.
	 */
	PostfixValueDouble(const PostfixValueDouble &Val) : PostfixValueBase(POSTFIX_VALUE_DOUBLE), val(Val.val ? new double(*Val.val) : NULL)
	{
	}

	/** Destructor, deletes value.
	 */
	~PostfixValueDouble()
	{
		this->Clear();
	}

	/** Assignment operator, will make sure to only allocate memory when needed.
	 * @param Val The value to copy into the current instance
	 * @return A reference of the current instance, for operator chaining purposes
	 */
	PostfixValueDouble &operator=(const PostfixValueDouble &Val)
	{
		if (this != &Val && Val.val)
		{
			if (this->val)
				*this->val = *Val.val;
			else
				this->val = new double(*Val.val);
		}
		return *this;
	}

	/** Gets the value.
	 * @return The value
	 */
	const double *Get() const
	{
		return this->val;
	}

	/** Creates a clone of the value.
	 * @return A clone of the value
	 */
	PostfixValueDouble *Clone() const
	{
		return new PostfixValueDouble(*this);
	}
};

/** Version of PostfixValue for Anope::string (this is used for anything that isn't a number) */
class PostfixValueString : public PostfixValueBase
{
	/** The value */
	Anope::string *val;

protected:
	/** Deletes the value to prevent memory leaks.
	 */
	void Clear()
	{
		delete this->val;
	}

public:
	/** Constructor that takes the value to store.
	 */
	PostfixValueString(const Anope::string &Val) : PostfixValueBase(POSTFIX_VALUE_STRING), val(new Anope::string(Val))
	{
	}

	/** Copy constructor, duplicates the value.
	 */
	PostfixValueString(const PostfixValueString &Val) : PostfixValueBase(POSTFIX_VALUE_STRING), val(Val.val ? new Anope::string(*Val.val) : NULL)
	{
	}

	/** Destructor, deletes value.
	 */
	~PostfixValueString()
	{
		this->Clear();
	}

	/** Assignment operator, will make sure to only allocate memory when needed.
	 * @param Val The value to copy into the current instance
	 * @return A reference of the current instance, for operator chaining purposes
	 */
	PostfixValueString &operator=(const PostfixValueString &Val)
	{
		if (this != &Val && Val.val)
		{
			if (this->val)
				*this->val = *Val.val;
			else
				this->val = new Anope::string(*Val.val);
		}
		return *this;
	}

	/** Gets the value.
	 * @return The value
	 */
	const Anope::string *Get() const
	{
		return this->val;
	}

	/** Creates a clone of the value.
	 * @return A clone of the value
	 */
	PostfixValueString *Clone() const
	{
		return new PostfixValueString(*this);
	}
};

/** Container for the list of Postfix values */
class Postfix
{
	/** A vector storing the list of Postfix values */
	std::vector<PostfixValueBase *> values;

public:
	/** Default constructor, creates an empty list.
	 */
	Postfix() : values()
	{
	}

	/** Copy constructor, will copy all values from another instance to this one.
	 */
	Postfix(const Postfix &postfix) : values()
	{
		this->append(postfix);
	}

	/** Destructor, will clear the list.
	 */
	~Postfix()
	{
		this->clear();
	}

	/** Assignment operator, will copy all values from one instance to this one, making sure to avoid memory leaks.
	 * @param postfix The instance to copy values from
	 * @return A reference of the current instance, for operator chaining purposes
	 */
	Postfix &operator=(const Postfix &postfix)
	{
		if (this != &postfix)
		{
			this->clear();
			this->append(postfix);
		}
		return *this;
	}

	/** Clears the list, deleting the allocated memory to prevent memory leaks.
	 */
	void clear()
	{
		for (unsigned y = 0, len = this->values.size(); y < len; ++y)
			delete this->values[y];
		this->values.clear();
	}

	/** Adds a new double value to the list.
	 * @param dbl The double value to add
	 */
	void add(double dbl)
	{
		this->values.push_back(new PostfixValueDouble(dbl));
	}

	/** Adds a new string value to the list.
	 * @param str The string value to add
	 */
	void add(const Anope::string &str)
	{
		this->values.push_back(new PostfixValueString(str));
	}

	/** Appends another instance to this one.
	 * @param postfix The instance to append from
	 */
	void append(const Postfix &postfix)
	{
		for (unsigned y = 0, len = postfix.values.size(); y < len; ++y)
			this->values.push_back(postfix.values[y]->Clone());
	}

	/** Determine if the list is empty or not.
	 * @return true if the list is empty, false otherwise
	 */
	bool empty() const
	{
		return this->values.empty();
	}

	/** Gets the size of the list.
	 * @return The size of the list.
	 */
	size_t size() const
	{
		return this->values.size();
	}

	/** Subscript operator, will get the value at the given index.
	 * @param index The index to look at
	 * @return The value for the given index
	 */
	PostfixValueBase *operator[](unsigned index)
	{
		if (index >= this->values.size())
			return NULL;
		return this->values[index];
	}

	/** Same as above, but for const safety. */
	const PostfixValueBase *operator[](unsigned index) const
	{
		if (index >= this->values.size())
			return NULL;
		return this->values[index];
	}
};

/** Convert an infix notation equation to a postfix notation equation, using the shunting-yard algorithm.
 * @param infix The infix notation equation to convert
 * @return A postfix notation equation
 *
 * Numbers are always stored in the postfix notation equation immediately, and operators are kept on a stack until they are
 * needed to be added to the postfix notation equation.
 * The conversion process goes as follows:
 * - Iterate through the infix notation equation, doing the following on each operation:
 *   - When a _ is encountered, add the number following it to the postfix notation equation, but make sure it's negative.
 *   - When a number is encountered, add it to the postfix notation equation.
 *   - When a function is encountered, add it to the operator stack and store a 1 on the arity stack.
 *   - When a constant is encountered, convert it to a number and add it to the postfix notation equation.
 *   - When an operator is encountered:
 *     - Check if we had any numbers prior to the operator, and fail if there were none.
 *     - Always add open parentheses to the operator stack.
 *     - When a close parenthesis is encountered, pop all operators until we get to an open parenthesis or the stack becomes
 *       empty, failing on the latter.
 *     - For all other operators, pop the stack if needed then add the operator to the stack.
 *   - When a comma is encountered, do the same as above for when a close parenthesis is encountered, but also check to make
 *     sure there was a function prior to the open parenthesis (if there is one). Increase the top of the arity stack by one.
 *   - If anything else is encountered, fail as it is an invalid value.
 * - If there were operators left on the operator stack, pop all of them, failing if anything is left on the stack (an open
 *   parenthesis will cause this).
 *
 * Of special note, when a function is being popped from the operator stack, if the function is allowed to take a variable
 * number of arguments, the number of arguments from the arity stack will be appended to the function's name, with an underscore
 * before that. The arity stack will be popped regardless.
 *
 * The improvement to the shunting-yard algorithm to allow functions to have arbitrary numbers of arguments comes from:
 * https://blog.kallisti.net.nz/2008/02/extension-to-the-shunting-yard-algorithm-to-allow-variable-numbers-of-arguments-to-functions/
 */
static Postfix InfixToPostfix(DiceServData &data, const Infix &infix)
{
	Postfix postfix;
	unsigned len = infix.str.length(), x = 0;
	bool prev_was_close = false, prev_was_number = false;
	std::stack<Anope::string> op_stack;
	std::stack<unsigned> arity_stack;
	spacesepstream tokens(infix.str);
	Anope::string token, lastone;
	// Loop over the space-separated tokens
	while (tokens.GetToken(token))
	{
		// If the start of the token is _, then we are dealing with a negative number
		if (token[0] == '_')
		{
			double number = 0.0;
			Anope::string token1 = token.substr(1);
			if (is_constant(token1))
			{
				if (token1.equals_ci("e"))
					number = -exp(1.0);
				else if (token1.equals_ci("pi"))
					number = -atan(1.0) * 4;
			}
			else
				number = is_number_str(token1) ? -Anope::Convert<double>(token1, std::numeric_limits<double>::quiet_NaN()) : std::numeric_limits<double>::quiet_NaN();
			if (is_infinite(number) || is_notanumber(number))
			{
				data.errCode = is_infinite(number) ? DICE_ERROR_OVERUNDERFLOW : DICE_ERROR_UNDEFINED;
				postfix.clear();
				return postfix;
			}
			postfix.add(number);
			prev_was_number = true;
		}
		else if (is_number(token[0]))
		{
			double number = is_number_str(token) ? Anope::Convert<double>(token, std::numeric_limits<double>::quiet_NaN()) : std::numeric_limits<double>::quiet_NaN();
			if (is_infinite(number) || is_notanumber(number))
			{
				data.errCode = is_infinite(number) ? DICE_ERROR_OVERUNDERFLOW : DICE_ERROR_UNDEFINED;
				postfix.clear();
				return postfix;
			}
			postfix.add(number);
			prev_was_number = true;
		}
		else if (is_function(token))
		{
			op_stack.push(token);
			arity_stack.push(1);
		}
		else if (is_constant(token))
		{
			double number = 0.0;
			if (token.equals_ci("e"))
				number = exp(1.0);
			else if (token.equals_ci("pi"))
				number = atan(1.0) * 4;
			postfix.add(number);
			prev_was_number = true;
		}
		else if (is_operator(token[0]))
		{
			if (!prev_was_number && token != "(" && token != ")" && !prev_was_close)
			{
				data.errPos = infix.positions[x];
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("That operator needs a number before it.");
				postfix.clear();
				return postfix;
			}
			lastone = op_stack.empty() ? "" : op_stack.top();
			prev_was_number = false;
			if (token == "(")
			{
				op_stack.push(token);
				prev_was_close = false;
			}
			else if (token == ")")
			{
				while (would_pop(token, lastone))
				{
					postfix.add(lastone);
					op_stack.pop();
					lastone = op_stack.empty() ? "" : op_stack.top();
				}
				if (lastone != "(")
				{
					data.errPos = infix.positions[x];
					data.errCode = DICE_ERROR_PARSE;
					data.errStr = _("There's a ')' here, but there wasn't a matching '(' earlier.");
					postfix.clear();
					return postfix;
				}
				else
					op_stack.pop();
				prev_was_close = true;
			}
			else
			{
				if (!would_pop(token, lastone))
					op_stack.push(token);
				else
				{
					while (would_pop(token, lastone))
					{
						if (is_function(lastone))
						{
							if (function_argument_count(lastone) < 0)
							{
								unsigned arity = arity_stack.top();
									Anope::string arityStr = ds_stringify(arity);
								lastone += "_" + arityStr;
							}
							arity_stack.pop();
						}
						postfix.add(lastone);
						op_stack.pop();
						lastone = op_stack.empty() ? "" : op_stack.top();
					}
					op_stack.push(token);
				}
				prev_was_close = false;
			}
		}
		else if (token[0] == ',')
		{
			lastone = op_stack.empty() ? "" : op_stack.top();
			while (would_pop(token, lastone))
			{
				postfix.add(lastone);
				op_stack.pop();
				lastone = op_stack.empty() ? "" : op_stack.top();
			}
			if (lastone != "(")
			{
				data.errPos = infix.positions[x];
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("That comma doesn't look like it's inside a function call.");
				postfix.clear();
				return postfix;
			}
			else
			{
				op_stack.pop();
				lastone = op_stack.empty() ? "" : op_stack.top();
				if (!is_function(lastone))
				{
					data.errPos = infix.positions[x];
					data.errCode = DICE_ERROR_PARSE;
					data.errStr = _("That comma doesn't look like it's inside a function call.");
					postfix.clear();
					return postfix;
				}
				else
				{
					op_stack.push("(");
					++arity_stack.top();
				}
			}
		}
		else
		{
			data.errPos = infix.positions[x];
			data.errCode = DICE_ERROR_PARSE;
			data.errStr = _("That expression contains an invalid character.");
			postfix.clear();
			return postfix;
		}
		x += token.length() + (x ? 1 : 0);
	}
	if (!op_stack.empty())
	{
		lastone = op_stack.top();
		while (would_pop("", lastone))
		{
			if (is_function(lastone))
			{
				if (function_argument_count(lastone) < 0)
				{
					unsigned arity = arity_stack.top();
								Anope::string arityStr = ds_stringify(arity);
					lastone += "_" + arityStr;
				}
				arity_stack.pop();
			}
			postfix.add(lastone);
			op_stack.pop();
			if (op_stack.empty())
				break;
			else
				lastone = op_stack.top();
		}
		if (!op_stack.empty())
		{
			data.errPos = len < infix.positions.size() ? infix.positions[len] : infix.positions[infix.positions.size() - 1] + 1;
			data.errCode = DICE_ERROR_PARSE;
			data.errStr = _("There's at least one '(' without a matching ')'.");
			postfix.clear();
			return postfix;
		}
	}
	return postfix;
}

/** Evaluate a postfix notation equation.
 * @param The postfix notation equation to evaluate
 * @return The final result after calculation of the equation
 *
 * The evaluation pops the required values from the operand stack for a function, and 2 values from the operand stack for an operator. The result
 * of either one is placed back on the operand stack, hopefully leaving a single result at the end.
 */
static double EvaluatePostfix(DiceServData &data, const Postfix &postfix)
{
	double val = 0;
	std::stack<double> num_stack;
	for (unsigned x = 0, len = postfix.size(); x < len; ++x)
	{
		if (postfix[x]->Type() == POSTFIX_VALUE_STRING)
		{
			const Anope::string *token_ptr = anope_dynamic_static_cast<const PostfixValueString *>(postfix[x])->Get();
			Anope::string token = token_ptr ? *token_ptr : "";
			if (token.empty())
			{
				data.errCode = DICE_ERROR_STACK;
				data.errStr = _("Something went wrong while evaluating that roll (empty token).");
				return 0;
			}
			if (is_function(token))
			{
				int function_arguments = function_argument_count(token);
				if (function_arguments < 0)
				{
					size_t underscore = token.find('_');
									int real_function_arguments = Anope::Convert<int>(token.substr(underscore + 1), 0);
					token = token.substr(0, underscore);
					if (real_function_arguments < -function_arguments)
					{
						data.errCode = DICE_ERROR_STACK;
						data.errStr = "Function needs at least " + ds_stringify(-function_arguments) + " arguments, but got " +
							ds_stringify(real_function_arguments) + ".";
						return 0;
					}
					function_arguments = real_function_arguments;
				}
				if (num_stack.empty() || num_stack.size() < static_cast<unsigned>(function_arguments))
				{
					data.errCode = DICE_ERROR_STACK;
					data.errStr = _("That function doesn't have enough numbers to work with.");
					return 0;
				}
				double val1 = num_stack.top();
				num_stack.pop();
				FunctionResult result;
				if (token.equals_ci("abs"))
				{
					val = std::abs(val1);
					result.SetNameAndResult("abs", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("acos"))
				{
					// Arc cosine is undefined outside the domain [-1, 1]
					if (std::abs(val1) > 1)
					{
						data.errCode = DICE_ERROR_UNDEFINED;
						return 0;
					}
					val = std::acos(val1);
					result.SetNameAndResult("acos", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("acosh"))
				{
					// Inverse hyperbolic cosine is undefined for any value less than 1
					if (val1 < 1)
					{
						data.errCode = DICE_ERROR_UNDEFINED;
						return 0;
					}
					val = acosh(val1);
					result.SetNameAndResult("acosh", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("asin"))
				{
					// Arc sine is undefined outside the domain [-1, 1]
					if (std::abs(val1) > 1)
					{
						data.errCode = DICE_ERROR_UNDEFINED;
						return 0;
					}
					val = std::asin(val1);
					result.SetNameAndResult("asin", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("asinh"))
				{
					val = asinh(val1);
					result.SetNameAndResult("asinh", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("atan"))
				{
					val = std::atan(val1);
					result.SetNameAndResult("atan", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("atan2"))
				{
					double val2 = val1;
					val1 = num_stack.top();
					num_stack.pop();
					val = std::atan2(val1, val2);
					result.SetNameAndResult("atan2", val);
					result.AddArgument(val1);
					result.AddArgument(val2);
				}
				else if (token.equals_ci("atanh"))
				{
					// Inverse hyperbolic tangent is undefined outside the domain (-1, 1)
					if (std::abs(val1) >= 1)
					{
						data.errCode = std::abs(val1) == 1 ? DICE_ERROR_DIV0 : DICE_ERROR_UNDEFINED;
						return 0;
					}
					val = atanh(val1);
					result.SetNameAndResult("atanh", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("cbrt"))
				{
					val = cbrt(val1);
					result.SetNameAndResult("cbrt", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("ceil"))
				{
					val = std::ceil(val1);
					result.SetNameAndResult("ceil", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("cos"))
				{
					val = std::cos(val1);
					result.SetNameAndResult("cos", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("cosh"))
				{
					val = std::cosh(val1);
					result.SetNameAndResult("cosh", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("deg"))
				{
					val = val1 * 45.0 / std::atan(1.0);
					result.SetNameAndResult("deg", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("exp"))
				{
					val = std::exp(val1);
					result.SetNameAndResult("exp", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("fac"))
				{
					// Negative factorials are considered undefined
					if (static_cast<int>(val1) < 0)
					{
						data.errCode = DICE_ERROR_UNDEFINED;
						return 0;
					}
					// Any factorials over 12 will be outside the range of a signed 32-bit integer, so don't bother to calculate them
					if (val1 > 12)
					{
						data.errCode = DICE_ERROR_OVERUNDERFLOW;
						return 0;
					}
					val = 1;
					for (unsigned n = 2; n <= static_cast<unsigned>(val1); ++n)
						val *= n;
					result.SetNameAndResult("fac", val);
					result.AddArgument(static_cast<unsigned>(val1));
				}
				else if (token.equals_ci("floor"))
				{
					val = std::floor(val1);
					result.SetNameAndResult("floor", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("log"))
				{
					// Logarithm is invalid for values 0 or less
					if (val1 <= 0)
					{
						data.errCode = DICE_ERROR_DIV0;
						return 0;
					}
					val = std::log(val1);
					result.SetNameAndResult("log", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("log10"))
				{
					// Logarithm is invalid for values 0 or less
					if (val1 <= 0)
					{
						data.errCode = DICE_ERROR_DIV0;
						return 0;
					}
					val = std::log10(val1);
					result.SetNameAndResult("log10", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("max"))
				{
					std::stack<double> args;
					args.push(val1);
					for (int i = 1; i < function_arguments; ++i)
					{
						double val2 = val1;
						val1 = num_stack.top();
						num_stack.pop();
						args.push(val1);
						val = val1 = std::max(val1, val2);
					}
					result.SetNameAndResult("max", val);
					while (!args.empty())
					{
						result.AddArgument(args.top());
						args.pop();
					}
				}
				else if (token.equals_ci("min"))
				{
					std::stack<double> args;
					args.push(val1);
					for (int i = 1; i < function_arguments; ++i)
					{
						double val2 = val1;
						val1 = num_stack.top();
						num_stack.pop();
						args.push(val1);
						val = val1 = std::min(val1, val2);
					}
					result.SetNameAndResult("min", val);
					while (!args.empty())
					{
						result.AddArgument(args.top());
						args.pop();
					}
				}
				else if (token.equals_ci("rad"))
				{
					val = val1 * std::atan(1.0) / 45.0;
					result.SetNameAndResult("rad", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("rand"))
				{
					double val2 = val1;
					val1 = num_stack.top();
					num_stack.pop();
					if (val1 > val2)
					{
						double tmp = val2;
						val2 = val1;
						val1 = tmp;
					}
					val = sfmtRNG.Random(static_cast<int>(val1), static_cast<int>(val2));
					result.SetNameAndResult("rand", val);
					result.AddArgument(static_cast<int>(val1));
					result.AddArgument(static_cast<int>(val2));
				}
				else if (token.equals_ci("round"))
				{
					val = my_round(val1);
					result.SetNameAndResult("round", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("sin"))
				{
					val = std::sin(val1);
					result.SetNameAndResult("sin", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("sinh"))
				{
					val = std::sinh(val1);
					result.SetNameAndResult("sinh", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("sqrt"))
				{
					// Because imaginary numbers are not being used, it is impossible to take the square root of a negative number
					if (val1 < 0)
					{
						data.errCode = DICE_ERROR_UNDEFINED;
						return 0;
					}
					val = std::sqrt(val1);
					result.SetNameAndResult("sqrt", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("tan"))
				{
					// Tangent is undefined for any value of pi / 2 + pi * n for all integers n
					if (!std::fmod(val1 + 2 * std::atan(1.0), std::atan(1.0) * 4))
					{
						data.errCode = DICE_ERROR_UNDEFINED;
						return 0;
					}
					val = std::tan(val1);
					result.SetNameAndResult("tan", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("tanh"))
				{
					val = std::tanh(val1);
					result.SetNameAndResult("tanh", val);
					result.AddArgument(val1);
				}
				else if (token.equals_ci("trunc"))
				{
					val = static_cast<int>(val1);
					result.SetNameAndResult("trunc", val);
					result.AddArgument(val1);
				}
				if (is_infinite(val) || is_notanumber(val))
				{
					data.errCode = is_infinite(val) ? DICE_ERROR_OVERUNDERFLOW : DICE_ERROR_UNDEFINED;
					return 0;
				}
				num_stack.push(val);
				data.AddToOpResults(result);
			}
			else if (is_operator(token[0]) && token.length() == 1)
			{
				if (num_stack.empty() || num_stack.size() < 2)
				{
					data.errCode = DICE_ERROR_STACK;
					data.errStr = _("That operator doesn't have enough numbers to work with.");
					return 0;
				}
				double val2 = num_stack.top();
				num_stack.pop();
				double val1 = num_stack.top();
				num_stack.pop();
				switch (token[0])
				{
					case '+':
						val = val1 + val2;
						break;
					case '-':
						val = val1 - val2;
						break;
					case '*':
						val = val1 * val2;
						break;
					case '/':
						// Prevent division by 0
						if (!val2)
						{
							data.errCode = DICE_ERROR_DIV0;
							return 0;
						}
						val = val1 / val2;
						break;
					case '%':
						// Prevent division by 0
						if (!val2)
						{
							data.errCode = DICE_ERROR_DIV0;
							return 0;
						}
						val = std::fmod(val1, val2);
						break;
					case '^':
						// Because imaginary numbers are not being used, it is impossible to take the power of a negative number to a non-integer exponent
						if (val1 < 0 && static_cast<int>(val2) != val2)
						{
							data.errCode = DICE_ERROR_UNDEFINED;
							return 0;
						}
						// Prevent division by 0
						if (!val1 && !val2)
						{
							data.errCode = DICE_ERROR_DIV0;
							return 0;
						}
						// 0 to a negative power is invalid
						if (!val1 && val2 < 0)
						{
							data.errCode = DICE_ERROR_OVERUNDERFLOW;
							return 0;
						}
						val = std::pow(val1, val2);
						break;
					case 'd':
					{
						// Make sure both the number of dice and the number of sides are within acceptable ranges
						if (val1 < 1 || val1 > DICE_MAX_DICE)
						{
							data.errCode = DICE_ERROR_UNACCEPTABLE_DICE;
							data.errNum = static_cast<int>(val1);
							return 0;
						}
						if (val2 < 1 || val2 > DICE_MAX_SIDES)
						{
							data.errCode = DICE_ERROR_UNACCEPTABLE_SIDES;
							data.errNum = static_cast<int>(val2);
							return 0;
						}
						DiceResult result = Dice(static_cast<int>(val1), static_cast<unsigned>(val2));
						data.AddToOpResults(result);
						val = result.Value();
					}
				}
				if (is_infinite(val) || is_notanumber(val))
				{
					data.errCode = is_infinite(val) ? DICE_ERROR_OVERUNDERFLOW : DICE_ERROR_UNDEFINED;
					return 0;
				}
				num_stack.push(val);
			}
		}
		else
		{
			const PostfixValueDouble *dbl = anope_dynamic_static_cast<const PostfixValueDouble *>(postfix[x]);
			const double *val_ptr = dbl->Get();
			if (!val_ptr)
			{
				data.errCode = DICE_ERROR_STACK;
				data.errStr = _("Something went wrong while evaluating that roll (missing number).");
				return 0;
			}
			num_stack.push(*val_ptr);
		}
	}
	val = num_stack.top();
	num_stack.pop();
	if (!num_stack.empty())
	{
		data.errCode = DICE_ERROR_STACK;
		data.errStr = _("That expression has too many numbers and can't be evaluated as written.");
		return 0;
	}
	return val;
}

/** Parse an infix notation expression and convert the expression to postfix notation.
 * @param infix The original expression, in infix notation, to convert to postfix notation
 * @return A postfix notation expression equivalent to the infix notation expression given, or an empty object if the infix notation expression could not be parsed or converted
 */
static Postfix DoParse(DiceServData &data, const Anope::string &infix)
{
	Infix infixcpy = FixInfix(infix);
	Postfix postfix;
	if (infixcpy.str.empty())
		return postfix;
	if (!CheckInfix(data, infixcpy))
		return postfix;
	Infix tokenized_infix = TokenizeInfix(infixcpy);
	if (tokenized_infix.str.empty())
		return postfix;
	postfix = InfixToPostfix(data, tokenized_infix);
	return postfix;
}

/** Evaluate a postfix notation expression.
 * @param postfix The postfix notation expression to evaluate
 * @return The final result after evaluation
 */
static double DoEvaluate(DiceServData &data, const Postfix &postfix)
{
	double ret = EvaluatePostfix(data, postfix);
	if (ret > std::numeric_limits<int>::max() || ret < std::numeric_limits<int>::min())
		data.errCode = DICE_ERROR_OVERUNDERFLOW;
	return ret;
}

const OperatorResultType &OperatorResultBase::Type() const
{
	return this->type;
}

DiceResult::DiceResult(int n, unsigned s) : OperatorResultBase(OPERATOR_RESULT_TYPE_DICE), num(n), sides(s), results()
{
}

void DiceResult::AddResult(unsigned result)
{
	this->results.push_back(result);
}

const std::vector<unsigned> &DiceResult::Results() const
{
	return this->results;
}

const unsigned &DiceResult::Sides() const
{
	return this->sides;
}

Anope::string DiceResult::DiceString() const
{
	return ds_stringify(this->num) + "d" + ds_stringify(this->sides);
}

unsigned DiceResult::Sum() const
{
	return std::accumulate(this->results.begin(), this->results.end(), 0u);
}

double DiceResult::Value() const
{
	return this->Sum();
}

Anope::string DiceResult::LongString() const
{
	std::ostringstream str;
	str << ds_stringify(this->num) << "d" << ds_stringify(this->sides) << "=(";
	bool first = true;
	for (size_t i = 0, len = this->results.size(); i < len; ++i)
	{
		if (!first)
			str << " ";
		str << ds_stringify(this->results[i]);
		first = false;
	}
	str << ")";
	return str.str();
}

Anope::string DiceResult::ShortString() const
{
	return ds_stringify(this->num) + "d" + ds_stringify(this->sides) + "=(" + ds_stringify(this->Sum()) + ")";
}

DiceResult *DiceResult::Clone() const
{
	return new DiceResult(*this);
}

FunctionResult::FunctionResult(const Anope::string &Name, double Result) : OperatorResultBase(OPERATOR_RESULT_TYPE_FUNCTION), name(Name), arguments(),
	result(Result)
{
}

void FunctionResult::SetNameAndResult(const Anope::string &Name, double Result)
{
	this->name = Name;
	this->result = Result;
}

void FunctionResult::AddArgument(double arg)
{
	this->arguments.push_back(arg);
}

double FunctionResult::Value() const
{
	return this->result;
}

Anope::string FunctionResult::LongString() const
{
	std::ostringstream str;
	str << this->name << "(";
	bool first = true;
	for (size_t i = 0, len = this->arguments.size(); i < len; ++i)
	{
		if (!first)
			str << ",";
		str << ds_stringify(this->arguments[i]);
		first = false;
	}
	str << ")=" << this->result;
	return str.str();
}

Anope::string FunctionResult::ShortString() const
{
	return this->LongString();
}

FunctionResult *FunctionResult::Clone() const
{
	return new FunctionResult(*this);
}

OperatorResults &OperatorResults::operator=(const OperatorResults &other)
{
	if (this != &other)
	{
		this->clear();
		this->append(other);
	}
	return *this;
}

void OperatorResults::add(const DiceResult &result)
{
	this->results.push_back(new DiceResult(result));
}

void OperatorResults::add(const FunctionResult &result)
{
	this->results.push_back(new FunctionResult(result));
}

void OperatorResults::append(const OperatorResults &other)
{
	for (unsigned y = 0, count = other.results.size(); y < count; ++y)
		this->results.push_back(other.results[y]->Clone());
}

bool OperatorResults::empty() const
{
	return this->results.empty();
}

void DiceServData::Reset()
{
	this->timesResults.clear();
	this->opResults.clear();
	this->results.clear();
	this->errCode = DICE_ERROR_NONE;
	this->errStr = "";
	this->errPos = 0u;
	this->errNum = 0;
}

/** Joins a parameters list by a space delimiter into a single string.
 * @param params The parameter list to join
 * @param firstParam The index of the first parameter to start joining from
 * @param lastParam The index of the last parameter to end joining at
 * @return A string of the parameters joined by a space delimiter
 */
static Anope::string Join(const std::vector<Anope::string> &params, size_t firstParam, size_t lastParam)
{
	Anope::string joinedString;
	for (size_t x = firstParam; x <= lastParam; ++x)
		joinedString += " " + params[x];
	joinedString.erase(0 ,1);
	return joinedString;
}

bool DiceServData::PreParse(CommandSource &source, const std::vector<Anope::string> &params, unsigned expectedChannelPos)
{
	User *user = source.GetUser();
	// Check for a ignore on the user or their registered nick, if any, and deny them access if they are ignored
	if (this->DiceServ->IsIgnored(user))
		return false;
	if (source.GetAccount() && this->DiceServ->IsIgnored(source.GetAccount()))
		return false;
	// Set up the dice, chan, and comment strings
	if (source.c)
	{
		if (params.size() < 2)
			return false;
		this->chanStr = params[0];
		this->diceStr = params[1];
		if (expectedChannelPos != 1)
			this->extraStr = Join(params, 2, expectedChannelPos);
		this->commentStr = params.size() > expectedChannelPos + 1 ? params[expectedChannelPos + 1] : "";
		this->sourceIsBot = true;
	}
	else
	{
		this->diceStr = params[0];
		if (expectedChannelPos != 1)
			this->extraStr = Join(params, 1, expectedChannelPos - 1);
		this->chanStr = params.size() > expectedChannelPos ? params[expectedChannelPos] : "";
		this->commentStr = params.size() > expectedChannelPos + 1 ? params[expectedChannelPos + 1] : "";
		this->sourceIsBot = false;
	}
	// If the channel doesn't start with #, we'll treat it as if it was part of the comment
	if (!this->chanStr.empty() && this->chanStr[0] != '#')
	{
		this->commentStr = this->chanStr + (this->commentStr.empty() ? "" : " ") + this->commentStr;
		this->chanStr = "";
	}
	/* If a channel was given, ignore the roll if the user isn't in the channel.
	 * Also, check if the channel has ignored rolls to it or if it's been moderated (+m) and the user has no status to the channel. */
	if (!this->chanStr.empty())
	{
		Channel *c = source.c ? *source.c : Channel::Find(this->chanStr);
		if (c)
		{
			if (!c->FindUser(user))
			{
				if (!source.c)
					source.Reply(CHAN_X_INVALID, this->chanStr.c_str());
				return false;
			}
			if (this->DiceServ->IsIgnored(c) || (c->ci ? this->DiceServ->IsIgnored(c->ci) : false) || c->MatchesList(user, "QUIET") || c->HasMode("MODERATED"))
				this->chanStr = "";
			if (this->chanStr.empty() && source.c)
				return false;
		}
		else
			this->chanStr = "";
	}
	// If a [ is found in the dice expression and the expression ends in a ], assume it is of an alternate group format of x[y] and convert to the x~y format instead
	size_t sbracket = this->diceStr.find('[');
	if (sbracket != Anope::string::npos && this->diceStr[this->diceStr.length() - 1] == ']')
	{
		this->diceStr.erase(this->diceStr.end() - 1);
		this->diceStr[sbracket] = '~';
	}
	// Extract the number of times expression, if any.
	size_t tilde = this->diceStr.find('~');
	if (tilde != Anope::string::npos)
	{
		this->timesPart = this->diceStr.substr(0, tilde);
		this->dicePart = this->diceStr.substr(tilde + 1);
	}
	else
		this->dicePart = this->diceStr;
	return true;
}

bool DiceServData::CheckMessageLengthPreProcess(CommandSource &source)
{
	this->maxMessageLength = 510;
	// The following parts are not going to be in the output string generated by DiceServ, but need to be checked anyways.
	BotInfo *bi = source.c ? *source.service : Config->GetClient("DiceServ");
	this->maxMessageLength -= bi->nick.length();
	this->maxMessageLength -= bi->GetIdent().length();
	this->maxMessageLength -= bi->host.length();
	this->maxMessageLength -= 7; // For the :, !, and @, plus the space after that and after the PRIVMSG/NOTICE and after the target and the : for the message
	this->maxMessageLength -= !this->chanStr.empty() && this->sourceIsBot ? 7 : 6; // inchan with BotServ bot == PRIVMSG, otherwise NOTICE
	this->maxMessageLength -= !this->chanStr.empty() ? this->chanStr.length() : source.GetUser()->nick.length(); // inchan uses channel's name, otherwise uses user's nick
	// The following parts are going to be in the output string generated by DiceServ, so don't modify the member variable.
	int restMaxMessageLength = this->maxMessageLength;
	restMaxMessageLength -= 7; // For the < > [ ] :, and the space before the [ and after the :
	if (!this->rollPrefix.empty())
		restMaxMessageLength -= this->rollPrefix.length(); // The prefix of the roll string itself
	if (!this->dicePrefix.empty())
		restMaxMessageLength -= this->dicePrefix.length(); // The prefix of the dice expression
	restMaxMessageLength -= this->diceStr.length(); // The dice expression itself
	if (!this->diceSuffix.empty())
		restMaxMessageLength -= this->diceSuffix.length(); // The suffix of the dice expression
	if (!this->chanStr.empty())
	{
		restMaxMessageLength -= 4; // "for "
		restMaxMessageLength -= source.GetUser()->nick.length(); // nick of user who used the command
	}
	if (!this->commentStr.empty())
		restMaxMessageLength -= this->commentStr.length() + 1; // Comment plus space
	// Check for overflow prior to adding in dice results
	if (restMaxMessageLength <= 0)
	{
		source.Reply(_("Dice result buffer has an overflow. This could be due to\n"
			"large values that are close to the limits or the size of\n"
			"your comment. Please enter some lower rolls or a smaller\n"
			"comment."));
		return false;
	}
	return true;
}

bool DiceServData::CheckMessageLengthPostProcess(CommandSource &source, const Anope::string &output) const
{
	if (this->maxMessageLength - static_cast<int>(output.length()) <= 0)
	{
		source.Reply(_("Dice result buffer has an overflow. This could be due to\n"
			"large values that are close to the limits or the size of\n"
			"your comment. Please enter some lower rolls or a smaller\n"
			"comment."));
		return false;
	}
	return true;
}

Anope::string DiceServData::GenerateLongExOutput() const
{
	std::ostringstream output;
	output << "<" << this->rollPrefix << " [" << this->dicePrefix << this->diceStr << this->diceSuffix << "]: ";

	if (this->isExtended)
	{
		if (!this->timesResults.empty() || !this->opResults.empty())
			output << "{";

		if (!this->timesResults.empty())
		{
			bool first = true;
			for (size_t i = 0, len = this->timesResults.size(); i < len; ++i)
			{
				if (!first)
					output << " ";
				output << this->timesResults[i]->LongString();
				first = false;
			}

			output << " ~ ";
		}
		if (!this->opResults.empty())
		{
			bool firstOp = true;

			for (size_t i = 0, len = this->opResults.size(); i < len; ++i)
			{
				if (!firstOp)
					output << " | ";
				bool first = true;
				for (size_t j = 0, len2 = this->opResults[i].size(); j < len2; ++j)
				{
					if (!first)
						output << " ";
					output << this->opResults[i][j]->LongString();
					first = false;
				}
				firstOp = false;
			}
		}

		if (!this->timesResults.empty() || !this->opResults.empty())
			output << "} ";
	}

	bool first = true;
	for (size_t i = 0, len = this->results.size(); i < len; ++i)
	{
		if (!first)
			output << " ";
		output << ds_stringify(this->results[i]);
		first = false;
	}

	output << ">";
	if (!this->commentStr.empty())
		output << " " << this->commentStr;

	return output.str();
}

Anope::string DiceServData::GenerateShortExOutput() const
{
	std::ostringstream output;
	output << "<" << this->rollPrefix << " [" << this->dicePrefix << this->diceStr << this->diceSuffix << "]: ";

	if (this->isExtended)
	{
		if (!this->timesResults.empty() || !this->opResults.empty())
			output << "{";

		if (!this->timesResults.empty())
		{
			bool first = true;
			for (size_t i = 0, len = this->timesResults.size(); i < len; ++i)
			{
				if (!first)
					output << " ";
				output << this->timesResults[i]->ShortString();
				first = false;
			}

			output << " ~ ";
		}
		if (!this->opResults.empty())
		{
			bool firstOp = true;

			for (size_t i = 0, len = this->opResults.size(); i < len; ++i)
			{
				if (!firstOp)
					output << " | ";
				bool first = true;
				for (size_t j = 0, len2 = this->opResults[i].size(); j < len2; ++j)
				{
					if (!first)
						output << " ";
					output << this->opResults[i][j]->ShortString();
					first = false;
				}
				firstOp = false;
			}
		}

		if (!this->timesResults.empty() || !this->opResults.empty())
			output << "} ";
	}

	bool first = true;
	for (size_t i = 0, len = this->results.size(); i < len; ++i)
	{
		if (!first)
			output << " ";
		output << ds_stringify(this->results[i]);
		first = false;
	}

	output << ">";
	if (!this->commentStr.empty())
		output << " " << this->commentStr;

	return output.str();
}

Anope::string DiceServData::GenerateNoExOutput() const
{
	std::ostringstream output;
	output << "<" << this->rollPrefix << " [" << this->dicePrefix << this->diceStr << this->diceSuffix << "]: ";

	bool first = true;
	for (size_t i = 0, len = this->results.size(); i < len; ++i)
	{
		if (!first)
			output << " ";
		output << ds_stringify(this->results[i]);
		first = false;
	}

	output << ">";
	if (!this->commentStr.empty())
		output << " " << this->commentStr;

	return output.str();
}

void DiceServData::StartNewOpResults()
{
	this->opResults.push_back(OperatorResults());
}

void DiceServData::AddToOpResults(const DiceResult &result)
{
	this->opResults[this->opResults.size() - 1].add(result);
}

void DiceServData::AddToOpResults(const FunctionResult &result)
{
	this->opResults[this->opResults.size() - 1].add(result);
}

void DiceServData::SetOpResultsAsTimesResults()
{
	this->timesResults = this->opResults[0];
	this->opResults.clear();
}

void DiceServData::Roll()
{
	this->DiceServ->Roller(*this);
}

DiceResult *DiceServData::Dice(int num, unsigned sides)
{
	return this->DiceServ->Dice(num, sides);
}

void DiceServData::HandleError(CommandSource &source)
{
	this->DiceServ->ErrorHandler(source, *this);
}

void DiceServData::SendReply(CommandSource &source, const Anope::string &output) const
{
	if (this->chanStr.empty())
		source.Reply(output);
	else if (this->sourceIsBot)
		IRCD->SendPrivmsg(*source.service, this->chanStr, output);
	else
		IRCD->SendNotice(Config->GetClient("DiceServ"), this->chanStr, output);
}

bool DiceServData::HasExtended() const
{
	bool opResultsHasExtended = false;
	for (int i = 0, len = this->opResults.size(); i < len; ++i)
		if (!this->opResults[i].empty())
		{
			opResultsHasExtended = true;
			break;
		}
	return (!this->timesPart.empty() && !this->timesResults.empty()) || opResultsHasExtended;
}

/** A middleman service to prevent the need for most of DiceServData's code being in the header (and thus only defined once here in the core).
 */
class DiceServDataHandler : public DiceServDataHandlerService
{
public:
	DiceServDataHandler(Module *m) : DiceServDataHandlerService(m)
	{
	}

	void Reset(DiceServData &data)
	{
		data.Reset();
	}

	bool PreParse(DiceServData &data, CommandSource &source, const std::vector<Anope::string> &params, unsigned expectedChannelPos)
	{
		return data.PreParse(source, params, expectedChannelPos);
	}

	bool CheckMessageLengthPreProcess(DiceServData &data, CommandSource &source)
	{
		return data.CheckMessageLengthPreProcess(source);
	}

	bool CheckMessageLengthPostProcess(const DiceServData &data, CommandSource &source, const Anope::string &output) const
	{
		return data.CheckMessageLengthPostProcess(source, output);
	}

	Anope::string GenerateLongExOutput(const DiceServData &data) const
	{
		return data.GenerateLongExOutput();
	}

	Anope::string GenerateShortExOutput(const DiceServData &data) const
	{
		return data.GenerateShortExOutput();
	}

	Anope::string GenerateNoExOutput(const DiceServData &data) const
	{
		return data.GenerateNoExOutput();
	}

	void StartNewOpResults(DiceServData &data)
	{
		data.StartNewOpResults();
	}

	void AddToOpResults(DiceServData &data, const DiceResult &result)
	{
		data.AddToOpResults(result);
	}

	void AddToOpResults(DiceServData &data, const FunctionResult &result)
	{
		data.AddToOpResults(result);
	}

	void SetOpResultsAsTimesResults(DiceServData &data)
	{
		data.SetOpResultsAsTimesResults();
	}

	void Roll(DiceServData &data)
	{
		data.Roll();
	}

	DiceResult *Dice(DiceServData &data, int num, unsigned sides)
	{
		return data.Dice(num, sides);
	}

	void HandleError(DiceServData &data, CommandSource &source)
	{
		data.HandleError(source);
	}

	void SendReply(const DiceServData &data, CommandSource &source, const Anope::string &output) const
	{
		data.SendReply(source, output);
	}

	bool HasExtended(const DiceServData &data) const
	{
		return data.HasExtended();
	}

	const std::vector<unsigned> &Results(const DiceResult &result) const
	{
		return result.Results();
	}

	const unsigned &Sides(const DiceResult &result) const
	{
		return result.Sides();
	}

	Anope::string DiceString(const DiceResult &result) const
	{
		return result.DiceString();
	}

	unsigned Sum(const DiceResult &result) const
	{
		return result.Sum();
	}

	DiceResult *Clone(const DiceResult &result) const
	{
		return result.Clone();
	}
};

/** A timer designed to load an old DiceServ database from Anope 1.8.x or pre-Anope 1.9.2 after the main database has loaded.
 */
class DiceServUpgradeTimer : public Timer
{
	Anope::string diceservdb;

public:
	DiceServUpgradeTimer(Module *creator, time_t timeout, const Anope::string &db) : Timer(creator, timeout),
		diceservdb(db)
	{
	}

	bool Tick() override;
};

/** DiceServ's core module, provides the interface for other modules to be able to use the roller.
 */
class DiceServCore : public Module, public DiceServService
{
	Reference<BotInfo> DiceServ;
	DiceServDataHandler DiceServHandler;
	SerializableExtensibleItem<bool> DiceServIgnore;

	/** Makes sure that a user who was ignored by their NickServ account is still ignored no matter what.
	 */
	void NickEvent(User *u)
	{
		if (u->Account() && this->IsIgnored(u->Account()))
			this->Ignore(u);
	}

public:
	DiceServCore(const Anope::string &modname, const Anope::string &creator) : Module(modname, creator, PSEUDOCLIENT | THIRD), DiceServService(this),
		DiceServHandler(this), DiceServIgnore(this, "diceserv_ignore")
	{
		this->SetAuthor(DiceServService::Author());
		this->SetVersion(DiceServService::Version());

		const Anope::string &diceservdb = Config->GetModule(this).Get<const Anope::string>("diceservdb", "");
		if (!diceservdb.empty())
		{
			std::ifstream oldDatabase(diceservdb.c_str(), std::ios::in | std::ios::binary);

			if (oldDatabase)
			{
				oldDatabase.close();

				if (Me->IsSynced())
					new DiceServUpgradeTimer(this, 0, diceservdb);
				else
					new DiceServUpgradeTimer(this, 1, diceservdb);
			}
		}
	}

	void OnReload(Configuration::Conf &conf) override
	{
		const Anope::string &dsnick = conf.GetModule(this).Get<const Anope::string>("client", "DiceServ");
		this->DiceServ = BotInfo::Find(dsnick, true);
	}

	/** Handles accessing HELP FUNCTIONS
	 */
	EventReturn OnPreCommand(CommandSource &source, Command *command, std::vector<Anope::string> &params) override
	{
		if (command->name.equals_ci("generic/help"))
		{
			Anope::string help = params.size() ? params[0] : "";

			if (help.equals_ci("FUNCTIONS"))
			{
				source.Reply(_("%s recognizes the following functions:\n"
					" \n"
					"    abs(\037x\037)         Absolute value of \037x\037\n"
					"    acos(\037x\037)        Arc cosine of \037x\037\n"
					"    acosh(\037x\037)       Inverse hyperbolic cosine of \037x\037\n"
					"    asin(\037x\037)        Arc sine of \037x\037\n"
					"    asinh(\037x\037)       Inverse hyperbolic sine of \037x\037\n"
					"    atan(\037x\037)        Arc tangent of \037x\037\n"
					"    atan2(\037y\037,\037x\037)     Arc tangent of \037y\037/\037x\037\n"
					"    atanh(\037x\037)       Inverse hyperbolic tangent of \037x\037\n"
					"    cbrt(\037x\037)        Cube root of \037x\037\n"
					"    ceil(\037x\037)        The next smallest integer greater than\n"
					"                   or equal to \037x\037\n"
					"    cos(\037x\037)         Cosine of \037x\037\n"
					"    cosh(\037x\037)        Hyperbolic cosine of \037x\037\n"
					"    deg(\037x\037)         Convert \037x\037 from radians to degrees\n"
					"    exp(\037x\037)         e (exponential value) to the power\n"
					"                   of \037x\037\n"
					"    fac(\037x\037)         Factorial of \037x\037\n"
					"    floor(\037x\037)       The next largest integer less than or\n"
					"                   equal to \037x\037\n"
					"    log(\037x\037)         Natural logarithm of \037x\037\n"
					"    log10(\037x\037)       Common logarithm of \037x\037\n"
					"    max(...)       Maximum of all values given (they must\n"
					"                   be separated by commas)\n"
					"    min(...)       Minimum of all values given (they must\n"
					"                   be separated by commas)\n"
					"    rad(\037x\037)         Convert \037x\037 from degrees to radians\n"
					"    rand(\037x\037,\037y\037)      Random value between \037x\037 and \037y\037\n"
					"    round(\037x\037)       Round \037x\037 to the nearest integer\n"
					"    sin(\037x\037)         Sine of \037x\037\n"
					"    sinh(\037x\037)        Hyperbolic sine of \037x\037\n"
					"    sqrt(\037x\037)        Square root of \037x\037\n"
					"    tan(\037x\037)         Tangent of \037x\037\n"
					"    tanh(\037x\037)        Hyperbolic tangent of \037x\037\n"
					"    trunc(\037x\037)       The integral portion of \037x\037\n"
					" \n"
					"NOTE: All trigonometric functions above (sine, cosine and\n"
					"tangent) return their values in radians."), this->DiceServ->nick.c_str());
				return EVENT_STOP;
			}
		}

		return EVENT_CONTINUE;
	}

	/** Handles adding a line for DiceServ status to NickServ's INFO command.
	 */
	void OnNickInfo(CommandSource &source, NickAlias *na, InfoFormatter &info, bool show_hidden) override
	{
		if (source.HasCommand("diceserv/info"))
			info[Anope::Format("%s Status", this->DiceServ->nick.c_str())] = this->IsIgnored(na->nc) ? _("Ignored") : _("Allowed");
	}

	/** Handles adding a line for DiceServ status to ChanServ's INFO command.
	 */
	void OnChanInfo(CommandSource &source, ChannelInfo *ci, InfoFormatter &info, bool show_all) override
	{
		if ((ci->HasExt("SECUREFOUNDER") ? source.IsFounder(ci) : source.AccessFor(ci).HasPriv("FOUNDER")) || source.HasCommand("diceserv/info"))
			info[Anope::Format("%s Status", this->DiceServ->nick.c_str())] = this->IsIgnored(ci) ? _("Ignored") : _("Allowed");
	}

	/** Displays the help header for the core of DiceServ.
	 */
	EventReturn OnPreHelp(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		if (*source.service == this->DiceServ && params.empty())
			source.Reply(_("\002%s\002 allows you to roll any number of dice with any\n"
				"number of sides. The output of the roll can either be output\n"
				"just to you, or you can have it notice the result to a\n"
				"channel. Available commands are listed below; to use them,\n"
				"type \002%s%s \037command\037\002. For more information on a\n"
				"specific command, type \002%s%s HELP \037command\037\002.\n"
				" "), this->DiceServ->nick.c_str(), "/msg ", this->DiceServ->nick.c_str(), "/msg ",
				this->DiceServ->nick.c_str());

		return EVENT_CONTINUE;
	}

	/** Displays the help footer for the core of DiceServ.
	 */
	void OnPostHelp(CommandSource &source, const std::vector<Anope::string> &params) override
	{
		if (*source.service == this->DiceServ && params.empty())
		{
			BotInfo *BotServ = Config->GetClient("BotServ");
			source.Reply(_(" \n"
				"\002%s\002 will check for syntax errors and tell you what\n"
				"errors you have.\n"
				" \n"
				"If a %s bot is in a channel, you can also trigger the\n"
				"both within the channel using fantasy commands. If a\n"
				"%s bot is in the channel, output will be said by the\n"
				"bot. Otherwise, it will be said by %s. Syntax of the\n"
				"fantasy commands can be found in the help of each command.\n"
				" \n"
				"%s by Naram Qashat (CyberBotX, cyberbotx@cyberbotx.com).\n"
				"Questions, comments, or concerns can be directed to email or\n"
				"to #DiceServ on jenna.cyberbotx.com."), this->DiceServ->nick.c_str(), BotServ ? BotServ->nick.c_str() : "BotServ",
				BotServ ? BotServ->nick.c_str() : "BotServ", this->DiceServ->nick.c_str(), this->DiceServ->nick.c_str());
		}
	}

	/** Updates the DiceServ ignore status of a user connecting if they were ignored on their NickServ account.
	 */
	void OnUserConnect(User *u, bool &) override
	{
		this->NickEvent(u);
	}

	/** Updates the DiceServ ignore status of a user who's nick was changed if they were ignored on their NickServ account.
	 */
	void OnUserNickChange(User *u, const Anope::string &) override
	{
		this->NickEvent(u);
	}

	/** If a user was ignored in DiceServ when they register a nick, then persist the ignore onto their account.
	 */
	void OnNickRegister(User *u, NickAlias *, const Anope::string &) override
	{
		if (this->IsIgnored(u))
			this->Ignore(u->Account());
	}

	/** Updates the DiceServ ignore status of a channel when someone joins it if it was ignored on its ChanServ account.
	 */
	void OnJoinChannel(User *, Channel *c) override
	{
		if (c->ci && this->IsIgnored(c->ci))
			this->Ignore(c);
	}

	/** If a channel was ignored in DiceServ when it gets registered, then persist the ignore onto the registered channel.
	 */
	void OnChanRegistered(ChannelInfo *ci) override
	{
		if (ci->c && this->IsIgnored(ci->c))
			this->Ignore(ci);
	}

	/** DiceServ error handler, will output an error message to the user if any errors occurred.
	 */
	void ErrorHandler(CommandSource &source, const DiceServData &data)
	{
		switch (data.errCode)
		{
			case DICE_ERROR_NONE:
				break;
			case DICE_ERROR_PARSE:
			{
				source.Reply(_("Sorry — I couldn't understand that roll request."));
				source.Reply(_("Expression: %s"), data.diceStr.c_str());
				if (!data.chanStr.empty())
					source.Reply(_("Target: %s"), data.chanStr.c_str());
				if (!data.commentStr.empty())
					source.Reply(_("Comment: %s"), data.commentStr.c_str());
				unsigned caret_pos = data.errPos > data.diceStr.length() ? data.diceStr.length() : data.errPos;
				Anope::string spaces(caret_pos, ' ');
				source.Reply(_("Error near character %u."), caret_pos + 1);
				source.Reply(_("Marker: %s^"), spaces.c_str());
				if (!data.errStr.empty())
					source.Reply(_("Details: %s"), data.errStr.c_str());
				source.Reply(_("Tip: try something like \0372d6+1\037 or \0371d20+5\037. For help: \002/msg %s HELP ROLL\002"), source.service->nick.c_str());
				break;
			}
			case DICE_ERROR_DIV0:
				source.Reply(_("That roll tried to divide by zero, so I couldn't evaluate it."));
				source.Reply(_("Expression: %s"), data.diceStr.c_str());
				break;
			case DICE_ERROR_UNDEFINED:
				source.Reply(_("That roll resulted in an undefined value, so I couldn't evaluate it."));
				source.Reply(_("Expression: %s"), data.diceStr.c_str());
				break;
			case DICE_ERROR_UNACCEPTABLE_DICE:
				if (data.errNum <= 0)
					source.Reply(_("The number of dice that you entered (\037%d\037) was under\n1. Please enter a number between 1 and %d."), data.errNum,
						DICE_MAX_DICE);
				else
					source.Reply(_("The number of dice that you entered (\037%d\037) was over the\nlimit of %d. Please enter a lower number of dice."),
						data.errNum, DICE_MAX_DICE);
				break;
			case DICE_ERROR_UNACCEPTABLE_SIDES:
				if (data.errNum <= 0)
					source.Reply(_("The number of sides that you entered (\037%d\037) was under\n1. Please enter a number between 1 and %d."), data.errNum,
						DICE_MAX_SIDES);
				else
					source.Reply(_("The number of sides that you entered (\037%d\037) was over the\nlimit of %d. Please enter a lower number of sides."),
						data.errNum, DICE_MAX_SIDES);
				break;
			case DICE_ERROR_UNACCEPTABLE_TIMES:
				if (data.errNum <= 0)
					source.Reply(_("The number of times that you entered (\037%d\037) was under\n1. Please enter a number between 1 and %d."), data.errNum,
						DICE_MAX_TIMES);
				else
					source.Reply(_("The number of times that you entered (\037%d\037) was over the\nlimit of %d. Please enter a lower number of times."),
						data.errNum, DICE_MAX_TIMES);
				break;
			case DICE_ERROR_OVERUNDERFLOW:
				source.Reply(_("That roll result was too large or too small to handle safely."));
				source.Reply(_("Expression: %s"), data.diceStr.c_str());
				break;
			case DICE_ERROR_STACK:
				source.Reply(_("Sorry — I couldn't evaluate that roll."));
				source.Reply(_("Expression: %s"), data.diceStr.c_str());
				if (!data.errStr.empty())
					source.Reply(_("Details: %s"), data.errStr.c_str());
				source.Reply(_("Tip: try a simpler expression, or ask an admin if this keeps happening."));
				break;
		}
	}

	/** DiceServ's core roller, handles parsing the actual expression and then executing it however many times is necessary.
	 */
	void Roller(DiceServData &data)
	{
		double v; // Stores the result of the dice expression
		int n = 1; // Temporary counter for number of sets to roll, defaults to rolling once
		// The following is for handling if there was a given number of times to roll
		if (!data.timesPart.empty())
		{
			if (data.dicePart.empty())
			{
				data.errCode = DICE_ERROR_PARSE;
				data.errStr = _("I didn't see any dice to roll there.");
				data.errPos = data.timesPart.length() + 1;
				return;
			}
			Postfix times_postfix = DoParse(data, data.timesPart);
			// If the parsing failed, leave
			if (times_postfix.empty())
				return;
			// Evaluate the expression
			data.StartNewOpResults();
			v = DoEvaluate(data, times_postfix);
			data.SetOpResultsAsTimesResults();
			times_postfix.clear();
			// Check if the evaluated number of times is out of bounds
			if (data.errCode == DICE_ERROR_NONE)
			{
				n = static_cast<int>(v);
				if (n < 1 || n > DICE_MAX_TIMES)
				{
					data.errCode = DICE_ERROR_UNACCEPTABLE_TIMES;
					data.errNum = n;
					return;
				}
			}
		}
		// As long as there was no error, roll the dice
		if (data.errCode == DICE_ERROR_NONE)
		{
			// Parse the dice
			Postfix dice_postfix = DoParse(data, data.dicePart);
			// If the parsing failed, leave
			if (dice_postfix.empty())
			{
				if (!data.timesPart.empty())
					data.errPos += data.timesPart.length() + 1;
				return;
			}
			// Roll as many sets as were requested
			for (; n > 0; --n)
			{
				// Evaluate the dice, then check for errors
				data.StartNewOpResults();
				v = DoEvaluate(data, dice_postfix);
				// As long as we didn't have an error, we will continue
				if (data.errCode == DICE_ERROR_NONE)
					// Round the result, if needed, and add it the buffer
					data.results.push_back(data.roundResults ? static_cast<int>(my_round(v)) : v);
				// Leave if there was an error
				else
				{
					if (!data.timesPart.empty())
						data.errPos += data.timesPart.length() + 1;
					return;
				}
			}
			dice_postfix.clear();
		}
	}

	/** A middleman function to roll dice, used currently by the Earthdawn command for generating bonus rolls.
	 */
	DiceResult *Dice(int num, unsigned sides)
	{
		return ::Dice(num, sides).Clone();
	}

	/** Add an ignore to the given object (usually a channel or nick).
	 * @param obj The extensible object to add an ignore to.
	 */
	void Ignore(Extensible *obj)
	{
		this->DiceServIgnore.Set(obj);
	}

	/** Remove an ignore from the given object (usually a channel or nick).
	 * @param obj The extensible object to remove an ignore from.
	 */
	void Unignore(Extensible *obj)
	{
		this->DiceServIgnore.Unset(obj);
	}

	/** Get if the given object (usually a channel or nick) is ignored.
	 * @param obj The extensible object to check ignore status of.
	 * @return true if the object is ignored, false otherwise.
	 */
	bool IsIgnored(Extensible *obj)
	{
		return this->DiceServIgnore.HasExt(obj);
	}
};

bool DiceServUpgradeTimer::Tick()
{
	if (Me->IsSynced())
	{
		DiceServCore *DiceServ = anope_dynamic_static_cast<DiceServCore *>(this->GetOwner());

		std::ifstream oldDatabase(this->diceservdb.c_str(), std::ios::in | std::ios::binary);

		do
		{
			std::string line;
			getline(oldDatabase, line);

			if (oldDatabase.eof())
				break;

			spacesepstream sep(line);
			Anope::string ignore_type, ignore_name;
			sep.GetToken(ignore_type);
			sep.GetToken(ignore_name);
			if (!ignore_type.empty() && !ignore_name.empty())
			{
				if (ignore_type.equals_ci("C"))
				{
					ChannelInfo *ci = ChannelInfo::Find(ignore_name);
					if (ci)
						DiceServ->Ignore(ci);
				}
				else if (ignore_type.equals_ci("N"))
				{
					NickAlias *na = NickAlias::Find(ignore_name);
					if (na)
						DiceServ->Ignore(na->nc);
				}
			}
		} while (true);

		oldDatabase.close();

		unlink(this->diceservdb.c_str());

		Log(DiceServ) << "Loaded old database, it has been deleted and ignore data will now be stored as metadata in main database. Please comment out the diceservdb directive in the diceserv module configuration block.";

		return false;
	}
}

MODULE_INIT(DiceServCore)
