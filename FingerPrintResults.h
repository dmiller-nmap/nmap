
/***************************************************************************
 * FingerPrintResults -- The FingerPrintResults class the results of OS    *
 * fingerprint matching against a certain host.                            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *  The Nmap Security Scanner is (C) 1995-2002 Insecure.Com LLC. This  *
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

#ifndef FINGERPRINTRESULTS_H
#define FINGERPRINTRESULTS_H

class FingerPrintResults;

#include "nmap.h"

/* Maximum number of results allowed in one of these things ... */
#define MAX_FP_RESULTS 36

struct OS_Classification_Results {
  struct OS_Classification *OSC[MAX_FP_RESULTS];
  double OSC_Accuracy[MAX_FP_RESULTS];
  int OSC_num_perfect_matches; // Number of perfect matches in OSC[\]
  int OSC_num_matches; // Number of matches total in OSC[] (and, of course, _accuracy[])
  int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, OSSCAN_SUCCESS, etc */
};

class FingerPrintResults {
 public: /* For now ... a lot of the data members should be made private */
  FingerPrintResults();
  ~FingerPrintResults();

  double accuracy[MAX_FP_RESULTS]; /* Percentage of match (1.0 == perfect 
				      match) in same order as pritns[] below */
  FingerPrint *prints[MAX_FP_RESULTS]; /* ptrs to matching references -- 
					      highest accuracy matches first */
  int num_perfect_matches; /* Number of 1.0 accuracy matches in prints[] */
  int num_matches; /* Total number of matches in prints[] */
  int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, 
			  OSSCAN_SUCCESS, etc */

  /* Ensures that the results are available and then returns them.  You should only call
   this AFTER all matching has been completed (because results are cached and won't change
   if new prints[] are added.)  All OS Classes in the results will be unique, and if there are 
   any perfect (accuracy 1.0) matches, only those will be returned */
  const struct OS_Classification_Results *getOSClassification();

  int osscan_opentcpport; /* Open port used for scannig (if one found -- 
			  otherwise -1) */
  int osscan_closedtcpport; /* Closed port used for scannig (if one found -- 
			    otherwise -1) */
  FingerPrint *FPs[10]; /* Fingerprint data obtained from host */
  int numFPs;
  int goodFP;

  /* Are the attributes of this fingerprint good enough to warrant submission to the official DB? */
  bool fingerprintSuitableForSubmission(); 
                                          

 private:
  bool isClassified; // Whether populateClassification() has been called
  /* Goes through fingerprinting results to populate OSR */

  void populateClassification();
  bool classAlreadyExistsInResults(struct OS_Classification *OSC);
  struct OS_Classification_Results OSR;
};

#endif /* FINGERPRINTRESULTS_H */
