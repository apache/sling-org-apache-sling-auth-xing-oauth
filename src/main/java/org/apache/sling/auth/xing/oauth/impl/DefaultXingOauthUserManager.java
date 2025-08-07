/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.xing.oauth.impl;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;

import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.auth.xing.api.AbstractXingUserManager;
import org.apache.sling.auth.xing.api.XingUser;
import org.apache.sling.auth.xing.oauth.XingOauth;
import org.apache.sling.auth.xing.oauth.XingOauthUserManager;
import org.apache.sling.auth.xing.oauth.XingOauthUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.osgi.service.component.propertytypes.ServiceRanking;
import org.osgi.service.component.propertytypes.ServiceVendor;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@ServiceRanking(0)
@ServiceVendor(XingOauth.SERVICE_VENDOR)
@ServiceDescription("Default User Manager for Sling Authentication XING OAuth")
@Designate(ocd = DefaultXingOauthUserManager.Config.class)
public class DefaultXingOauthUserManager extends AbstractXingUserManager implements XingOauthUserManager {

    @Reference
    private SlingRepository slingRepository;

    private static final String FIRSTNAME_PROPERTY = "firstname";

    private static final String LASTNAME_PROPERTY = "lastname";

    @ObjectClassDefinition(name = "Apache Sling Authentication XING OAuth “Default User Manager”",
            description = "Default User Manager for Sling Authentication XING OAuth")
    public @interface Config {

        @AttributeDefinition
        boolean org_apache_sling_auth_xing_oauth_impl_DefaultXingOauthUserManager_user_create_auto() default DEFAULT_AUTO_CREATE_USER; //NOSONAR

        @AttributeDefinition
        boolean org_apache_sling_auth_xing_oauth_impl_DefaultXingOauthUserManager_user_update_auto() default DEFAULT_AUTO_UPDATE_USER; //NOSONAR
    }

    private final Logger logger = LoggerFactory.getLogger(DefaultXingOauthUserManager.class);

    public DefaultXingOauthUserManager() {
    }

    @Activate
    protected void activate(final Config config) {
        logger.debug("activate");
        configure(config);
    }

    @Modified
    protected void modified(final Config config) {
        logger.debug("modified");
        configure(config);
    }

    @Deactivate
    protected void deactivate(final ComponentContext componentContext) {
        logger.debug("deactivate");
        if (session != null) {
            session.logout();
            session = null;
        }
    }

    protected synchronized void configure(final Config config) {
        autoCreateUser = config.org_apache_sling_auth_xing_oauth_impl_DefaultXingOauthUserManager_user_create_auto();
        autoUpdateUser = config.org_apache_sling_auth_xing_oauth_impl_DefaultXingOauthUserManager_user_update_auto();
    }

    @Override
    protected SlingRepository getSlingRepository() {
        return slingRepository;
    }

    @Override
    public User createUser(final Credentials credentials) {
        logger.debug("create user");
        final XingUser xingUser = XingOauthUtil.getXingUser(credentials);
        if (xingUser == null) {
            return null;
        }

        try {
            final String userId = xingUser.getId(); // TODO make configurable

            final Session session = getSession();
            final UserManager userManager = getUserManager(session);
            final User user = userManager.createUser(userId, null);

            // TODO disable user on create?
            final ValueFactory valueFactory = session.getValueFactory();
            final Value firstnameValue = valueFactory.createValue(xingUser.getFirstName());
            final Value lastnameValue = valueFactory.createValue(xingUser.getLastName());
            user.setProperty(FIRSTNAME_PROPERTY, firstnameValue);
            user.setProperty(LASTNAME_PROPERTY, lastnameValue);
            session.save();
            return user;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    @Override
    public User updateUser(Credentials credentials) {
        logger.debug("update user");
        final XingUser xingUser = XingOauthUtil.getXingUser(credentials);
        if (xingUser == null) {
            return null;
        }

        try {
            final Session session = getSession();
            final User user = getUser(credentials);
            final ValueFactory valueFactory = session.getValueFactory();

            final boolean firstnameUpdated = updateUserProperty(user, valueFactory, FIRSTNAME_PROPERTY, xingUser.getFirstName());
            final boolean lastnameUpdated = updateUserProperty(user, valueFactory, LASTNAME_PROPERTY, xingUser.getLastName());
            if (firstnameUpdated || lastnameUpdated) {
                session.save();
            }

            return user;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return null;
        }
    }

    private boolean updateUserProperty(final User user, final ValueFactory valueFactory, final String property, final String string) throws RepositoryException {
        final Value[] values = user.getProperty(property);
        if (values != null && values.length > 0) {
            if (string.equals(values[0].getString())) {
                return false;
            }
        }
        final Value value = valueFactory.createValue(string);
        user.setProperty(property, value);
        return true;
    }

}
