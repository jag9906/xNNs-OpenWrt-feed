/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Portions copyright 2005-2013 Steinar H. Gunderson <sgunderson@bigfoot.com>.
 * Licensed under the same terms as the rest of Apache.
 */

/**
 * @file  itk/seccomp.h
 * @brief Utility functions for seccomp support
 *
 * @defgroup APACHE_MPM_ITK Apache ITK
 * @ingroup APACHE_INTERNAL
 * @{
 */

#ifndef APACHE_MPM_SECCOMP_H
#define APACHE_MPM_SECCOMP_H

void restrict_setuid_range(uid_t min_uid, uid_t max_uid, gid_t min_gid, gid_t max_gid);

#endif /* AP_MPM_SECCOMP_H */
/** @} */
