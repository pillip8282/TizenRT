/****************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
/****************************************************************************
 *
 *   Copyright (C) 2007-2012, 2015 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

#include <tinyara/config.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <errno.h>
#include <debug.h>
#include <net/if.h>
#include <tinyara/netmgr/net_vfs.h>
#include "netstack.h"

/****************************************************************************
 * Name: net_checksd
 *
 * Description:
 *   Check if the socket descriptor is valid for the provided TCB and if it
 *   supports the requested access.  This trivial operation is part of the
 *   fdopen() operation when the fdopen() is performed on a socket descriptor.
 *   It simply performs some sanity checking before permitting the socket
 *   descriptor to be wrapped as a C FILE stream.
 *
 ****************************************************************************/
int net_checksd(int sd, int oflags)
{
	struct netstack *st = get_netstack();
	return st->ops->checksd(sd, oflags);
}

/****************************************************************************
 * Function: net_clone
 *
 * Description:
 *   Performs the low level, common portion of net_dupsd() and net_dupsd2()
 *
 ****************************************************************************/

int net_clone(FAR struct socket *sock1, FAR struct socket *sock2)
{
	struct netstack *st = get_netstack();
	return st->ops->clone(sock1, sock2);
}

/****************************************************************************
 * Function: net_dupsd
 *
 * Description:
 *   Clone a socket descriptor to an arbitray descriptor number.  If file
 *   descriptors are implemented, then this is called by dup() for the case
 *   of socket file descriptors.  If file descriptors are not implemented,
 *   then this function IS dup().
 *
 ****************************************************************************/
int net_dupsd(int sockfd)
{
	struct netstack *st = get_netstack();
	return st->ops->dup(sockfd);
}

/****************************************************************************
 * Function: net_dupsd2
 *
 * Description:
 *   Clone a socket descriptor to an arbitray descriptor number.  If file
 *   descriptors are implemented, then this is called by dup2() for the case
 *   of socket file descriptors.  If file descriptors are not implemented,
 *   then this function IS dup2().
 *
 ****************************************************************************/

int net_dupsd2(int sockfd1, int sockfd2)
{
	struct netstack *st = get_netstack();
	return st->ops->dup2(sockfd1, sockfd2);
}

/****************************************************************************
 * Function: net_close
 *
 * Description:
 *   Performs the close operation on socket descriptors
 *
 * Parameters:
 *   sockfd   Socket descriptor of socket
 *
 * Returned Value:
 *   0 on success; -1 on error with errno set appropriately.
 *
 * Assumptions:
 *
 ****************************************************************************/

int net_close(int sockfd)
{
	struct netstack *st = get_netstack();
	return st->ops->close(sockfd);
}

/****************************************************************************
 * Function: net_poll
 *
 * Description:
 *   poll() waits for one of a set of file descriptors to become ready to
 *   perform I/O.
 *
  * Returned Value:
 *   0 on success; -1 on error with errno set appropriately.
 *
 * Assumptions:
 *
 ****************************************************************************/
int net_poll(int fd, struct pollfd *fds, bool setup)
{
	struct netstack *st = get_netstack();
	return st->ops->poll(fd, fds, setup);
}

/****************************************************************************
 * Name: net_ioctl
 *
 * Description:
 *   Perform network device specific operations.
 *
 * Parameters:
 *   sockfd   Socket descriptor of device
 *   cmd      The ioctl command
 *   arg      The argument of the ioctl cmd
 *
 * Return:
 *   >=0 on success (positive non-zero values are cmd-specific)
 *   On a failure, -1 is returned with errno set appropriately
 *
 *   EBADF
 *     'sockfd' is not a valid descriptor.
 *   EFAULT
 *     'arg' references an inaccessible memory area.
 *   ENOTTY
 *     'cmd' not valid.
 *   EINVAL
 *     'arg' is not valid.
 *   ENOTTY
 *     'sockfd' is not associated with a network device.
 *   ENOTTY
 *      The specified request does not apply to the kind of object that the
 *      descriptor 'sockfd' references.
 *
 ****************************************************************************/
extern int netdev_imsfioctl(FAR struct socket *sock, int cmd, FAR struct ip_msfilter *imsf);
extern int netdev_ifrioctl(FAR struct socket *sock, int cmd, FAR struct ifreq *req);
extern int netdev_nmioctl(FAR struct socket *sock, int cmd, void  *arg);


int net_ioctl(int sockfd, int cmd, unsigned long arg)
{
	FAR struct socket *sock = NULL;
	int ret = -ENOTTY;

	/* Check if this is a valid command.  In all cases, arg is a pointer that has
	 * been cast to unsigned long.  Verify that the value of the to-be-pointer is
	 * non-NULL.
	 */
	if (!((_FIOCVALID(cmd)) ||  (_SIOCVALID(cmd)))) {
		ret = -ENOTTY;
		goto errout;
	}

	/* ToDo:  Verify that the sockfd corresponds to valid, allocated socket */
	/* sock = get_socket(sockfd); */
	/* if (NULL == sock) { */
	/* 	ret = -EBADF; */
	/* 	goto errout; */
	/* } */

	/* Execute the command */
	struct netstack *st = get_netstack();
	if (st) {
		ret = st->ops->ioctl(sockfd, cmd, arg);
	}
	if (ret == -ENOTTY) {
		ret = netdev_ifrioctl(sock, cmd, (FAR struct ifreq *)((uintptr_t)arg));
	}

#ifdef CONFIG_NET_NETMON
	if (ret == -ENOTTY) {
		ret = netdev_nmioctl(sock, cmd, (void *)((uintptr_t)arg));
	}
#endif                          /* CONFIG_NET_NETMON */
#ifdef CONFIG_NET_IGMP
	if (ret == -ENOTTY) {
		ret = netdev_imsfioctl(sock, cmd, (FAR struct ip_msfilter *)((uintptr_t)arg));
	}
#endif							/* CONFIG_NET_IGMP */
#ifdef CONFIG_NET_ROUTE
	if (ret == -ENOTTY) {
		ret = netdev_rtioctl(sock, cmd, (FAR struct rtentry *)((uintptr_t)arg));
	}
#endif							/* CONFIG_NET_ROUTE */

	/* Check for success or failure */
	if (ret >= 0) {
		return ret;
	}

	/* On failure, set the errno and return -1 */
errout:
	errno = -ret;
	return ERROR;
}


/****************************************************************************
 * Name: net_vfcntl
 *
 * Description:
 *   Performs fcntl operations on socket
 *
 * Input Parameters:
 *   sockfd - Socket descriptor of the socket to operate on
 *   cmd    - The fcntl command.
 *   ap     - Command-specific arguments
 *
 * Returned Value:
 *   Zero (OK) is returned on success; -1 (ERROR) is returned on failure and
 *   the errno value is set appropriately.
 *
 ****************************************************************************/

int net_vfcntl(int sockfd, int cmd, va_list ap)
{

	FAR struct socket *sock = (struct socket *)get_socket(sockfd);
	int err = 0;
	int ret = 0;

	nvdbg("sockfd=%d cmd=%d\n", sockfd, cmd);

	/* Verify that the sockfd corresponds to valid, allocated socket */

	if (!sock) {
		err = EBADF;
		goto errout;
	}

	/* Interrupts must be disabled in order to perform operations on socket structures */

	// flags = net_lock();
	switch (cmd) {
	case F_DUPFD:
		/* Return a new file descriptor which shall be the lowest numbered
		 * available (that is, not already open) file descriptor greater than
		 * or equal to the third argument, arg, taken as an integer of type
		 * int. The new file descriptor shall refer to the same open file
		 * description as the original file descriptor, and shall share any
		 * locks.  The FD_CLOEXEC flag associated  with the new file descriptor
		 * shall be cleared to keep the file open across calls to one of the
		 * exec functions.
		 */

	{
		struct netstack *st = get_netstack();
		ret = st->ops->dup(sockfd);
	}
	break;

	case F_GETFD:
		/* Get the file descriptor flags defined in <fcntl.h> that are associated
		 * with the file descriptor fd.  File descriptor flags are associated
		 * with a single file descriptor and do not affect other file descriptors
		 * that refer to the same file.
		 */

	case F_SETFD:
		/* Set the file descriptor flags defined in <fcntl.h>, that are associated
		 * with fd, to the third argument, arg, taken as type int. If the
		 * FD_CLOEXEC flag in the third argument is 0, the file shall remain open
		 * across the exec functions; otherwise, the file shall be closed upon
		 * successful execution of one  of  the  exec  functions.
		 */

		err = ENOSYS;			/* F_GETFD and F_SETFD not implemented */
		break;

	case F_GETFL:
		/* Get the file status flags and file access modes, defined in
		 * <fcntl.h>, for the file description associated with fd. The file
		 * access modes can be extracted from the return value using the
		 * mask O_ACCMODE, which is defined  in <fcntl.h>. File status flags
		 * and file access modes are associated with the file description
		 * and do not affect other file descriptors that refer to the same
		 * file with different open file descriptions.
		 */

	{
		struct netstack *st = get_netstack();
		ret = st->ops->fcntl(sockfd, cmd, ap);
	}
	break;

	case F_SETFL:
		/* Set the file status flags, defined in <fcntl.h>, for the file description
		 * associated with fd from the corresponding  bits in the third argument,
		 * arg, taken as type int. Bits corresponding to the file access mode and
		 * the file creation flags, as defined in <fcntl.h>, that are set in arg shall
		 * be ignored. If any bits in arg other than those mentioned here are changed
		 * by the application, the result is unspecified.
		 */

	{
		struct netstack *st = get_netstack();
		ret = st->ops->fcntl(sockfd, cmd, ap);
	}

	break;

	case F_GETOWN:
		/* If fd refers to a socket, get the process or process group ID specified
		 * to receive SIGURG signals when out-of-band data is available. Positive values
		 * indicate a process ID; negative values, other than -1, indicate a process group
		 * ID. If fd does not refer to a socket, the results are unspecified.
		 */

	case F_SETOWN:
		/* If fd refers to a socket, set the process or process group ID specified
		 * to receive SIGURG signals when out-of-band data is available, using the value
		 * of the third argument, arg, taken as type int. Positive values indicate a
		 * process ID; negative values, other than -1, indicate a process group ID. If
		 * fd does not refer to a socket, the results are unspecified.
		 */

	case F_GETLK:
		/* Get the first lock which blocks the lock description pointed to by the third
		 * argument, arg, taken as a pointer to type struct flock, defined in <fcntl.h>.
		 * The information retrieved shall overwrite the information passed to fcntl() in
		 * the structure flock. If no lock is found that would prevent this lock from being
		 * created, then the structure shall be left unchanged except for the lock type
		 * which shall be set to F_UNLCK.
		 */

	case F_SETLK:
		/* Set or clear a file segment lock according to the lock description pointed to
		 * by the third argument, arg, taken as a pointer to type struct flock, defined in
		 * <fcntl.h>. F_SETLK can establish shared (or read) locks (F_RDLCK) or exclusive
		 * (or write) locks (F_WRLCK), as well  as  to  remove  either  type  of  lock  (F_UNLCK).
		 * F_RDLCK, F_WRLCK, and F_UNLCK are defined in <fcntl.h>. If a shared or exclusive
		 * lock cannot be set, fcntl() shall return immediately with a return value of -1.
		 */

	case F_SETLKW:
		/* This command shall be equivalent to F_SETLK except that if a shared or exclusive
		 * lock is blocked by other locks, the thread shall wait until the request can be
		 * satisfied. If a signal that is to be caught is received while fcntl() is waiting
		 * for a region, fcntl() shall be interrupted. Upon return from the signal handler,
		 * fcntl() shall return -1 with errno set to [EINTR], and the lock operation shall
		 * not be done.
		 */

		err = ENOSYS;			/* F_GETOWN, F_SETOWN, F_GETLK, F_SETLK, F_SETLKW */
		break;

	default:
		err = EINVAL;
		break;
	}

	// net_unlock(flags);

errout:
	if (err != 0) {
		errno = err;
		return ERROR;
	}
	return ret;
}


/****************************************************************************
 * Name: net_initlist
 *
 * Description:
 *   Initialize a list of sockets for a new task
 *
 * Input Parameters:
 *   list -- A reference to the pre-allocated socket list to be initialized.
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void net_initlist(FAR struct socketlist *list)
{
	/* ToDo: Initialize the list access mutex */
	return;
}

/****************************************************************************
 * Name: net_releaselist
 *
 * Description:
 *   Release resources held by the socket list
 *
 * Input Parameters:
 *   list -- A reference to the pre-allocated socket list to be un-initialized.
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void net_releaselist(FAR struct socketlist *list)
{
	/*	Todo */
	return;
}
