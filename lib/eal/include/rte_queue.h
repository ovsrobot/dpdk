/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Original Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 */

#ifndef _RTE_QUEUE_H_
#define _RTE_QUEUE_H_

/**
 * @file
 *  Defines macro's that exist in the FreeBSD version of queue.h
 *  which are missing in other versions.
 */

#include <sys/queue.h>

/*
 * This file defines four types of data structures: singly-linked lists,
 * singly-linked tail queues, lists and tail queues.
 *
 * Below is a summary of implemented functions where:
 *  o  means the macro exists in original version
 *  +  means the macro is added here
 *  -  means the macro is not available
 *  s  means the macro is available but is slow (runs in O(n) time)
 *
 *				SLIST	LIST	STAILQ	TAILQ
 * _HEAD			o	o	o	o
 * _HEAD_INITIALIZER		o	o	o	o
 * _ENTRY			o	o	o	o
 * _INIT			o	o	o	o
 * _EMPTY			o	o	o	o
 * _FIRST			o	o	o	o
 * _NEXT			o	o	o	o
 * _FOREACH			o	o	o	o
 * _FOREACH_FROM		+	+	+	+
 * _FOREACH_SAFE		+	+	+	+
 * _FOREACH_FROM_SAFE		+	+	+	+
 * _FOREACH_REVERSE		-	-	-	o
 * _FOREACH_REVERSE_FROM	-	-	-	+
 * _FOREACH_REVERSE_SAFE	-	-	-       +
 * _FOREACH_REVERSE_FROM_SAFE	-	-	-	+
 * _INSERT_HEAD			o	o	o	o
 * _INSERT_BEFORE		-	o	-	o
 * _INSERT_AFTER		o	o	o	o
 * _INSERT_TAIL			-	-	o	o
 * _CONCAT			s	s	o	o
 * _REMOVE_AFTER		o	-	o	-
 * _REMOVE_HEAD			o	o	o	o
 * _REMOVE			s	o	s	o
 *
 */


/*
 * Singly-linked List declarations.
 */
#ifndef SLIST_FOREACH_FROM
#define	SLIST_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) ? (var) : SLIST_FIRST((head)));		\
	    (var);							\
	    (var) = SLIST_NEXT((var), field))
#endif

#ifndef SLIST_FOREACH_SAFE
#define	SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = SLIST_FIRST((head));				\
	    (var) && ((tvar) = SLIST_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#ifndef SLIST_FOREACH_FROM_SAFE
#define	SLIST_FOREACH_FROM_SAFE(var, head, field, tvar)			\
	for ((var) = ((var) ? (var) : SLIST_FIRST((head)));		\
	    (var) && ((tvar) = SLIST_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif


/*
 * Singly-linked Tail queue declarations.
 */
#ifndef STAILQ_FOREACH_FROM
#define	STAILQ_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) ? (var) : STAILQ_FIRST((head)));		\
	   (var);							\
	   (var) = STAILQ_NEXT((var), field))
#endif

#ifndef STAILQ_FOREACH_SAFE
#define	STAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = STAILQ_FIRST((head));				\
	    (var) && ((tvar) = STAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#ifndef STAILQ_FOREACH_FROM_SAFE
#define	STAILQ_FOREACH_FROM_SAFE(var, head, field, tvar)		\
	for ((var) = ((var) ? (var) : STAILQ_FIRST((head)));		\
	    (var) && ((tvar) = STAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

/*
 * List declarations.
 */
#ifndef LIST_FOREACH_FROM
#define	LIST_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) ? (var) : LIST_FIRST((head)));		\
	    (var);							\
	    (var) = LIST_NEXT((var), field))
#endif

#ifndef LIST_FOREACH_SAFE
#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = LIST_FIRST((head));				\
	    (var) && ((tvar) = LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#ifndef LIST_FOREACH_FROM_SAFE
#define	LIST_FOREACH_FROM_SAFE(var, head, field, tvar)			\
	for ((var) = ((var) ? (var) : LIST_FIRST((head)));		\
	    (var) && ((tvar) = LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

/*
 * Tail queue declarations.
 */
#ifndef TAILQ_FOREACH_FROM
#define TAILQ_FOREACH_FROM(var, head, field)				\
	for ((var) = ((var) ? (var) : TAILQ_FIRST((head)));		\
	    (var);							\
	    (var) = TAILQ_NEXT((var), field))
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = TAILQ_FIRST((head));				\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#ifndef TAILQ_FOREACH_FROM_SAFE
#define TAILQ_FOREACH_FROM_SAFE(var, head, field, tvar)			\
	for ((var) = ((var) ? (var) : TAILQ_FIRST((head)));		\
	    (var) && ((tvar) = TAILQ_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#ifndef TAILQ_FOREACH_REVERSE_FROM
#define TAILQ_FOREACH_REVERSE_FROM(var, head, headname, field)		\
	for ((var) = ((var) ? (var) : TAILQ_LAST((head), headname));	\
	    (var);							\
	    (var) = TAILQ_PREV((var), headname, field))
#endif

#ifndef TAILQ_FOREACH_REVERSE_SAFE
#define TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	for ((var) = TAILQ_LAST((head), headname);			\
	    (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1);	\
	    (var) = (tvar))
#endif

#ifndef TAILQ_FOREACH_REVERSE_FROM_SAFE
#define TAILQ_FOREACH_REVERSE_FROM_SAFE(var, head, headname, field, tvar)\
	for ((var) = ((var) ? (var) : TAILQ_LAST((head), headname));	\
	    (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1);	\
	    (var) = (tvar))
#endif

#endif /* !_RTE_QUEUE_H_ */
