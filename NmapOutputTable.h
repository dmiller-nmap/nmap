
/***********************************************************************
 * NmapOutputTable.h -- A relatively simple class for organizing Nmap  *
 * output into an orderly table for display to the user.               *
 *                                                                     *
 ***********************************************************************
 *  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  *
 *  program is free software; you can redistribute it and/or modify    *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; Version 2.  This guarantees your  *
 *  right to use, modify, and redistribute this software under certain *
 *  conditions.  If this license is unacceptable to you, we may be     *
 *  willing to sell alternative licenses (contact sales@insecure.com). *
 *                                                                     *
 *  If you received these files with a written license agreement       *
 *  stating terms other than the (GPL) terms above, then that          *
 *  alternative license agreement takes precendence over this comment. *
 *                                                                     *
 *  Source is provided to this software because we believe users have  *
 *  a right to know exactly what a program is going to do before they  *
 *  run it.  This also allows you to audit the software for security   *
 *  holes (none have been found so far).                               *
 *                                                                     *
 *  Source code also allows you to port Nmap to new platforms, fix     *
 *  bugs, and add new features.  You are highly encouraged to send     *
 *  your changes to fyodor@insecure.org for possible incorporation     *
 *  into the main distribution.  By sending these changes to Fyodor or *
 *  one the insecure.org development mailing lists, it is assumed that *
 *  you are offering Fyodor the unlimited, non-exclusive right to      *
 *  reuse, modify, and relicense the code.  This is important because  *
 *  the inability to relicense code has caused devastating problems    *
 *  for other Free Software projects (such as KDE and NASM).  Nmap     *
 *  will always be available Open Source.  If you wish to specify      *
 *  special license conditions of your contributions, just say so      *
 *  when you send them.                                                *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  *
 *  General Public License for more details (                          *
 *  http://www.gnu.org/copyleft/gpl.html ).                            *
 *                                                                     *
 ***********************************************************************/

/* $Id$ */

#ifndef NMAPOUTPUTTABLE_H
#define NMAPOUTPUTTABLE_H

#include <assert.h>

#ifndef __attribute__
#define __attribute__(args)
#endif

/**********************  DEFINES/ENUMS ***********************************/

/**********************  STRUCTURES  ***********************************/

/**********************  CLASSES     ***********************************/

struct NmapOutputTableCell {
  char *str;
  int strlength;
  bool weAllocated; // If we allocated str, we must free it.
};

class NmapOutputTable {
 public:
  // Create a table of the given dimensions
  NmapOutputTable(int nrows, int ncols);
  ~NmapOutputTable();

  // Copy specifies whether we must make a copy of item.  Otherwise we'll just save the
  // ptr (and you better not free it until this table is destroyed ).  Skip the itemlen parameter if you
  // don't know (and the function will use strlen).
  void addItem(unsigned int row, unsigned int column, bool copy, char *item, int itemlen = -1);
  // Like addItem except this version takes a prinf-style format string followed by varargs
  void addItemFormatted(unsigned int row, unsigned int column, const char *fmt, ...)
    __attribute__ ((format (printf, 4, 5)));
  // Returns the maximum size neccessary to create a printableTable() (the 
  // actual size could be less);
  int printableSize();

  // This function sticks the entire table into a character buffer.
  // Note that the buffer is likely to be reused if you call the
  // function again, and it will also be invalidated if you free the
  // Table.  if size is not NULL, it will be filled with the size of
  // the ASCII table in bytes (not including the terminating NUL
  char *printableTable(int *size);

 private:

  // The table, squished into 1D.  Access a member via getCellAddy
  struct NmapOutputTableCell *table;
  struct NmapOutputTableCell *getCellAddy(unsigned int row, unsigned int col) {
    assert(row < numRows);  assert(col < numColumns);
    return table + row * numColumns + col;
  }
  int *maxColLen; // An array that gives the maximum length of any member of each column 
                  // (excluding terminator)
  // Array that tells the number of valid (> 0 length) items in each row
  int *itemsInRow; 
  unsigned int numRows;  
  unsigned int numColumns;
  char *tableout; // If printableTable() is called, we returnthis
  int tableoutsz; // Amount of space ALLOCATED for tableoutsz.  Includes space allocated for NUL.
};


/**********************  PROTOTYPES  ***********************************/


#endif /* NMAPOUTPUTTABLE_H */





