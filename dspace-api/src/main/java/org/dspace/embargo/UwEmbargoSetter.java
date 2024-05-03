package org.dspace.embargo;

import java.sql.SQLException;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.dspace.authorize.AuthorizeException;
import org.dspace.authorize.ResourcePolicy;
import org.dspace.authorize.factory.AuthorizeServiceFactory;
import org.dspace.authorize.service.AuthorizeService;
import org.dspace.authorize.service.ResourcePolicyService;
import org.dspace.content.DCDate;
import org.dspace.content.Item;
import org.dspace.core.Context;
import org.dspace.core.Constants;
import org.dspace.content.DSpaceObject;
import org.dspace.content.Collection;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;


// Extends DayTableEmbargoSetter to handle whether to apply embargo to UW_Users group permission

public class UwEmbargoSetter extends DayTableEmbargoSetter
{
    /** log4j logger */
    private static Logger log = LogManager.getLogger(UwEmbargoSetter.class);
    private String lastTerms = null;

    /**
     * Override parseTerms solely to set lastTerms for use by generatePolicies() 
     */
    @Override
    public DCDate parseTerms(Context context, Item item, String terms)
        throws SQLException, AuthorizeException {

        lastTerms = terms;
        return super.parseTerms(context, item, terms);
    }


    /**
     * Custom embargo application to accomodate UW_Users permission and whether to apply embargo there
     */
    @Override
    protected void generatePolicies(Context context, Date embargoDate,
                                    String reason, DSpaceObject dso, Collection owningCollection)
        throws SQLException, AuthorizeException {

        // add only embargo policy
        if (embargoDate != null) {

            List<Group> authorizedGroups = getAuthorizeService()
                .getAuthorizedGroups(context, owningCollection, Constants.DEFAULT_ITEM_READ);

            // look for anonymous
            boolean isAnonymousInPlace = false;
            for (Group g : authorizedGroups) {
                if (StringUtils.equals(g.getName(), Group.ANONYMOUS)) {
                    isAnonymousInPlace = true;
                }
            }
            if (!isAnonymousInPlace) {
                // add policies for all the groups
                for (Group g : authorizedGroups) {
                    ResourcePolicy rp = getAuthorizeService()
                        .createOrModifyPolicy(null, context, null, g, null, embargoDate,
                                              Constants.READ, reason, dso);
                    if (rp != null) {
                        getResourcePolicyService().update(context, rp);
                    }
                }

            } else {
                // add policy just for anonymous
                ResourcePolicy rp = getAuthorizeService()
                    .createOrModifyPolicy(null, context, null,
                                          EPersonServiceFactory.getInstance()
                                                               .getGroupService()
                                                               .findByName(context, Group.ANONYMOUS),
                                          null, embargoDate, Constants.READ, reason, dso);
                if (rp != null) {
                    getResourcePolicyService().update(context, rp);
                }
            }


            // If embargo also applies to UW_Users, apply embargo there, too
            if (!lastTerms.contains("Restrict to UW")) {

                // look for UW_Users
                boolean isUWUsersInPlace = false;
                
                // Group uwUsers = Group.findByName(context, "UW_Users"); REPLACED WITH BELOW
                Group uwUsers = EPersonServiceFactory.getInstance().getGroupService().findByName(context, "UW_Users");

                UUID idUWUsers = uwUsers.getID();
                for(Group g : authorizedGroups) {
                    if(g.getID() == idUWUsers) {
                        isUWUsersInPlace = true;
                        break;
                    }
                }

                // Embargo UW_Users
                if (isUWUsersInPlace) {
                    log.info("Applying embargo to UW_Users"); 
                    // ResourcePolicy rp = AuthorizeManager.createOrModifyPolicy(null, context, null, idUWUsers, null, embargoDate, Constants.READ, reason, dso); REPLACED WITH BELOW
                    ResourcePolicy rp = getAuthorizeService().createOrModifyPolicy(null, context, null, uwUsers, null, embargoDate, Constants.READ, reason, dso);
                    if (rp != null) {
                        // rp.update(); REPLACED WITH BELOW
                        getResourcePolicyService().update(context, rp);
                    }
                } else {
                    log.info("No UW_Users group found, skipping embargo here");
                }
            } 
            else {
                log.info("Embargo permits UW access, skipping embargo application to UW_Users");
            }
        }
    }

    private AuthorizeService getAuthorizeService() {
        if (authorizeService == null) {
            authorizeService = AuthorizeServiceFactory.getInstance().getAuthorizeService();
        }
        return authorizeService;
    }

    private ResourcePolicyService getResourcePolicyService() {
        if (resourcePolicyService == null) {
            resourcePolicyService = AuthorizeServiceFactory.getInstance().getResourcePolicyService();
        }
        return resourcePolicyService;
    }
}