package org.dspace.embargo;

import java.sql.SQLException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Properties;
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
import org.dspace.services.factory.DSpaceServicesFactory;


// Extends DayTableEmbargoSetter to handle whether to apply embargo to UW_Users group permission

public class UwEmbargoSetter extends DayTableEmbargoSetter
{
    /** log4j logger */
    private static Logger log = LogManager.getLogger(UwEmbargoSetter.class);
    // Carries the terms from parseTerms() to generatePolicies(). Per-thread rather than a
    // plain field: this is a shared "single" plugin instance and embargoes are set on
    // concurrent submission threads, so a plain field could let one item's generatePolicies
    // read another item's terms. parseTerms() always runs before generatePolicies() on the
    // same thread, so each thread reads back exactly the value it wrote.
    private final ThreadLocal<String> lastTerms = new ThreadLocal<>();

    /**
     * Override parseTerms solely to set lastTerms for use by generatePolicies()
     *
     * NOTE: The day-table lookup below is intentionally copied from
     * DayTableEmbargoSetter rather than delegated to super.parseTerms(). This
     * works around an upstream bug in DayTableEmbargoSetter.parseTerms(), which
     * passes a millisecond value to Instant.ofEpochSecond() (should be
     * Instant.ofEpochMilli()), producing lift dates ~1000x too far in the future.
     * Do NOT reduce this method to a super.parseTerms() call while that bug
     * remains; doing so would silently reintroduce the incorrect embargo dates.
     * getTermProperties() is likewise copied because it is private in the parent.
     */
    @Override
    public DCDate parseTerms(Context context, Item item, String terms)
        throws SQLException, AuthorizeException {

        lastTerms.set(terms);

        String termsOpen = DSpaceServicesFactory.getInstance().getConfigurationService()
                                                .getProperty("embargo.terms.open");
        Properties termProps = getTermProperties();

        if (terms != null) {
            if (termsOpen.equals(terms)) {
                return EmbargoServiceImpl.FOREVER;
            }
            String days = termProps.getProperty(terms);
            if (days != null && days.length() > 0) {
                long lift = Instant.now().toEpochMilli() +
                    (Long.parseLong(days) * 24 * 60 * 60 * 1000);
                return new DCDate(ZonedDateTime.ofInstant(Instant.ofEpochMilli(lift), ZoneOffset.UTC));
            }
        }
        return null;
    }

    /**
     * Get term properties from configuration
     *
     * @return Properties
     */
    private Properties getTermProperties() {
        Properties termProps = new Properties();

        String terms[] = DSpaceServicesFactory.getInstance().getConfigurationService()
                                              .getArrayProperty("embargo.terms.days");

        if (terms != null) {
            for (String term : terms) {
                String[] parts = term.trim().split(":");
                termProps.setProperty(parts[0].trim(), parts[1].trim());
            }
        }

        return termProps;
    }


    /**
     * Custom embargo application to accomodate UW_Users permission and whether to apply embargo there
     */
    @Override
    protected void generatePolicies(Context context, LocalDate embargoDate,
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
        String terms = lastTerms.get();
        if (terms != null && terms.contains("Restrict to UW")) {
            // Check if UW_Users group is authorized
            boolean uwUsersGroupIsAuthorized = false;
            Group uwUsers = EPersonServiceFactory.getInstance().getGroupService().findByName(context, "UW_Users");
            UUID idUWUsers = uwUsers.getID();
            for(Group g : authorizedGroups) {
                if(g.getID().equals(idUWUsers)) {
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