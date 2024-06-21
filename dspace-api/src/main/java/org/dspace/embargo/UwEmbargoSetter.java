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

        if (embargoDate == null) {
            return;
        }

        List<Group> authorizedGroups = getAuthorizeService()
            .getAuthorizedGroups(context, owningCollection, Constants.DEFAULT_ITEM_READ);

        // Check if Anonymous group is authorized
        boolean anonGroupIsAuthorized = false;
        for (Group g : authorizedGroups) {
            if (StringUtils.equals(g.getName(), Group.ANONYMOUS)) {
                anonGroupIsAuthorized = true;
                break;
            }
        }

        // If the Anonymous group is authorized, add an embargoed READ policy for it
        // (This is the case for both "UW Restricted" and "Delay release" embargoes)
        if (anonGroupIsAuthorized) {
            ResourcePolicy rp = getAuthorizeService()
                .createOrModifyPolicy(null, context, null,
                                        EPersonServiceFactory.getInstance()
                                                            .getGroupService()
                                                            .findByName(context, Group.ANONYMOUS),
                                        null, embargoDate, Constants.READ, reason, dso);
            if (rp != null) {
                log.info("Adding embargoed READ policy for Anonymous group"); 
                getResourcePolicyService().update(context, rp);
            }
        } 

        // If embargo is a "UW Restricted" type...
        if (lastTerms.contains("Restrict to UW")) {
            // Check if UW_Users group is authorized
            boolean uwUsersGroupIsAuthorized = false;
            Group uwUsers = EPersonServiceFactory.getInstance().getGroupService().findByName(context, "UW_Users");
            UUID idUWUsers = uwUsers.getID();
            for(Group g : authorizedGroups) {
                if(g.getID() == idUWUsers) {
                    uwUsersGroupIsAuthorized = true;
                    break;
                }
            }

            // If the UW_Users group is authorized, add an non-embargoed READ policy for it
            if (uwUsersGroupIsAuthorized) {
                ResourcePolicy rp = getAuthorizeService()
                    .createOrModifyPolicy(null, context, null, uwUsers, 
                                            null, null, Constants.READ, reason, dso);
                if (rp != null) {
                    log.info("Adding non-embargoed READ policy for UW_Users group"); 
                    getResourcePolicyService().update(context, rp);
                }
            } else {
                log.info("UW_Users group not authorized, no policy created for it");
            }
        } 
        else {
            log.info("Embargo is 'Delay release' type, no UW_Users policy created");
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