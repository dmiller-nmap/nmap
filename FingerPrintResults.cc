
/***********************************************************************
 * FingerPrintResults -- The FingerPrintResults class the results of   *
 * OS fingerprint matching against a certain host.                     *
 *                                                                     *
 ***********************************************************************
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
 ***********************************************************************/

/* $Id$ */

#include "FingerPrintResults.h"
#include "osscan.h"
#include "NmapOps.h"

extern NmapOps o;

FingerPrintResults::FingerPrintResults() {
  num_perfect_matches = num_matches = 0;
  overall_results = OSSCAN_NOMATCHES;
  memset(accuracy, 0, sizeof(accuracy));
  isClassified = false;
  osscan_opentcpport = osscan_closedtcpport = -1;
  memset(FPs, 0, sizeof(FPs));
  numFPs = goodFP = 0;
}

FingerPrintResults::~FingerPrintResults() {
  int i;

  /* Free OS fingerprints of OS scanning was done */
  for(i=0; i < numFPs; i++) {
    freeFingerPrint(FPs[i]);
    FPs[i] = NULL;
  }
  numFPs = 0;

}

const struct OS_Classification_Results *FingerPrintResults::getOSClassification() {
  if (!isClassified) { populateClassification(); isClassified = true; }
  return &OSR;
}

  /* Are the attributes of this fingerprint good enough to warrant submission to the official DB? */
bool FingerPrintResults::fingerprintSuitableForSubmission() {
  // TODO:  There are many more tests I could (and should) add.  Maybe related to
  // UDP test, TTL, etc.
  if (o.scan_delay > 500) // This can screw up the sequence timing
    return false;

  if (osscan_opentcpport < 0 || osscan_closedtcpport < 0 ) // then results won't be complete
    return false;

  return true;
}


/* Goes through fingerprinting results to populate OSR */
void FingerPrintResults::populateClassification() {
  int printno, classno;

  OSR.OSC_num_perfect_matches = OSR.OSC_num_matches = 0;
  OSR.overall_results = OSSCAN_SUCCESS;

  if (overall_results == OSSCAN_TOOMANYMATCHES) {
    // The normal classification overflowed so we don't even have all the perfect matches,
    // I don't see any good reason to do classification.
    OSR.overall_results = OSSCAN_TOOMANYMATCHES;
    return;
  }

  for(printno = 0; printno < num_matches; printno++) {
    // a single print may have multiple classifications
    for(classno = 0; classno < prints[printno]->num_OS_Classifications; classno++) {
      if (!classAlreadyExistsInResults(&(prints[printno]->OS_class[classno]))) {
	// Then we have to add it ... first ensure we have room
	if (OSR.OSC_num_matches == MAX_FP_RESULTS) {
	  // Out of space ... if the accuracy of this one is 100%, we have a problem
	  if (accuracy[printno] == 1.0) OSR.overall_results = OSSCAN_TOOMANYMATCHES;
	  return;
	}

	// We have space, but do we even want this one?  No point
	// including lesser matches if we have 1 or more perfect
	// matches.
	if (OSR.OSC_num_perfect_matches > 0 && accuracy[printno] < 1.0) {
	  return;
	}

	// OK, we will add the new class
	OSR.OSC[OSR.OSC_num_matches] = &(prints[printno]->OS_class[classno]);
	OSR.OSC_Accuracy[OSR.OSC_num_matches] = accuracy[printno];
	if (accuracy[printno] == 1.0) OSR.OSC_num_perfect_matches++;
	OSR.OSC_num_matches++;
      }
    }
  }

  if (OSR.OSC_num_matches == 0)
    OSR.overall_results = OSSCAN_NOMATCHES;

  return;
}

// Go through any previously enterted classes to see if this is a dupe;
bool FingerPrintResults::classAlreadyExistsInResults(struct OS_Classification *OSC) {
  int i;

  for (i=0; i < OSR.OSC_num_matches; i++) {
    if (!strcmp(OSC->OS_Vendor, OSR.OSC[i]->OS_Vendor)  &&
	!strcmp(OSC->OS_Family, OSR.OSC[i]->OS_Family)  &&
	!strcmp(OSC->Device_Type, OSR.OSC[i]->Device_Type) &&
	!strcmp(OSC->OS_Generation? OSC->OS_Generation : "", 
		OSR.OSC[i]->OS_Generation? OSR.OSC[i]->OS_Generation : "")) {
    // Found a duplicate!
    return true;
    }
  }

  // Went through all the results -- no duplicates found
  return false;
}

