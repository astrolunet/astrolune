/*
 * Does astrolune/base.h compile as C++ on its own?
 *
 * One translation unit per public header, each including only that header. The
 * combined header_all.cpp cannot answer this question: a header that forgets to
 * include a dependency still compiles there, because a neighbour included it
 * first. The failure only appears for the consumer who reaches for that one
 * header, which is the consumer this file stands in for.
 *
 * These translation units define nothing. The compiler succeeding is the result.
 *
 * This file is not a joke. The joke is you expecting something interesting here.
 */

#include "astrolune/base.h"
