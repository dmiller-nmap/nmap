
/***************************************************************************
 * NmapOutputTable.cc -- A relatively simple class for organizing Nmap     *
 * output into an orderly table for display to the user.                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
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
 ***************************************************************************/

/* $Id$ */

#include "NmapOutputTable.h"
#include "utils.h"

#include <stdlib.h>

NmapOutputTable::NmapOutputTable(int nrows, int ncols) {
  numRows = nrows;
  numColumns = ncols;
  assert(numRows > 0);
  assert(numColumns > 0);
  table = (struct NmapOutputTableCell *) safe_zalloc(sizeof(struct NmapOutputTableCell) * nrows * ncols);
  maxColLen = (int *) safe_zalloc(sizeof(*maxColLen) * ncols);
  itemsInRow = (int *) safe_zalloc(sizeof(*itemsInRow) * nrows);
  tableout = NULL;
  tableoutsz = 0;
}

NmapOutputTable::~NmapOutputTable() {
  unsigned int col, row;
  struct NmapOutputTableCell *cell;

  for(row = 0; row < numRows; row++) {
    for(col = 0; col < numColumns; col++) {
      cell = getCellAddy(row, col);
      if (cell->weAllocated) {
	assert(cell->str);
	free(cell->str);
      }
    }
  }

  free(table);
  free(maxColLen);
  free(itemsInRow);
  if (tableout) free(tableout);
}

void NmapOutputTable::addItem(unsigned int row, unsigned int column, bool copy, char *item, 
			      int itemlen) {
  struct NmapOutputTableCell *cell;

  assert(row < numRows);
  assert(column < numColumns);

  if (itemlen < 0)
    itemlen = strlen(item);

  if (itemlen == 0)
    return;

  cell = getCellAddy(row, column);
  assert(cell->str == NULL); // I'll worry about replacing members if I ever need it
  itemsInRow[row]++;

  cell->strlength = itemlen;

  if (copy) {
    cell->str = (char *) safe_malloc(itemlen + 1);
    memcpy(cell->str, item, itemlen);
    cell->str[itemlen] = '\0';
  } else {
    cell->str = item;
  }
  cell->weAllocated = copy;

  if (maxColLen[column] < itemlen)
    maxColLen[column] = itemlen;

  return;
}

// Like addItem except this version takes a prinf-style format string 
// followed by varargs
void NmapOutputTable::addItemFormatted(unsigned int row, 
					  unsigned int column, 
					  const char *fmt, ...) {
  unsigned int res;
  va_list ap; 
  va_start(ap,fmt);
  char buf[4096];
  res = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (res < 0 || res > sizeof(buf))
    fatal("NmapOutputTable only supports adding up to 4096 to a cell via addItemFormatString.");

  addItem(row, column, true, buf, res);

  return;
}

// Returns the maximum size neccessary to create a printableTable() (the 
// actual size could be less);
int NmapOutputTable::printableSize() {

  int rowlen = 0;
  unsigned int i;

  for(i = 0; i < numColumns; i++) {
    rowlen += maxColLen[i];
  }

  /* Add the delimeter between each column, and the final newline */
  rowlen += numColumns;
  
  return rowlen * numRows;

}

 // This function sticks the entire table into a character buffer.
 // Note that the buffer is likely to be reused if you call the
 // function again, and it will also be invalidated if you free the
 // Table.  if size is not NULL, it will be filled with the size of
 // the ASCII table in bytes (not including the terminating NUL

char *NmapOutputTable::printableTable(int *size) {
  unsigned int col, row;
  int maxsz = printableSize();
  char *p;
  int clen = 0;
  int i;
  struct NmapOutputTableCell *cell;
  int validthisrow;

  if (maxsz >= tableoutsz) {
    tableoutsz = maxsz + 1;
    tableout = (char *) safe_realloc(tableout, tableoutsz);
  }
  p = tableout;

  for(row = 0; row < numRows; row++) {
    validthisrow = 0;
    for(col = 0; col < numColumns; col++) {
      cell = getCellAddy(row, col);
      clen = maxColLen[col];
      if (cell->strlength > 0) {
	memcpy(p, cell->str,  cell->strlength);
	p += cell->strlength;
	validthisrow++;
      }
      // No point leaving trailing spaces ...
      if (validthisrow < itemsInRow[row]) {
	for(i=cell->strlength; i <= clen; i++) // one extra because of space between columns
	  *(p++) = ' ';
      }
    }
    *(p++) = '\n';
  }
  *p = '\0';
  if (size) *size = p - tableout;
  return tableout;
}
