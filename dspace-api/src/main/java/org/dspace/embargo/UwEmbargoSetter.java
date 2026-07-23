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
import org.dspace.content.Bitstream;
import org.dspace.content.Bundle;
import org.dspace.content.Collection;
import org.dspace.content.DCDate;
import org.dspace.content.DSpaceObject;
import org.dspace.content.Item;
import org.dspace.content.factory.ContentServiceFactory;
import org.dspace.core.Constants;
import org.dspace.core.Context;
import org.dspace.embargo.factory.EmbargoServiceFactory;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.license.CreativeCommonsServiceImpl;
import org.dspace.services.factory.DSpaceServicesFactory;


// Extends DayTableEmbargoSetter to handle whether to apply embargo to UW_Users group permission

public class UwEmbargoSetter extends DayTableEmbargoSetter {
    /** log4j logger */
    private static Logger log = LogManager.getLogger(UwEmbargoSetter.class);

    /**
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
     * Overridden (bundle/bitstream loop copied from DefaultEmbargoSetter) so the
     * embargo terms can be read from the item's metadata here and passed to
     * generatePolicies() as an explicit parameter, keeping the setter stateless.
     */
    @Override
    public void setEmbargo(Context context, Item item)
        throws SQLException, AuthorizeException {

        String terms = getTermsFromItem(item);
        DCDate liftDate = EmbargoServiceFactory.getInstance().getEmbargoService()
                                               .getEmbargoTermsAsDate(context, item);
        // Unlike the parent, guard against a null lift date (e.g. terms metadata
        // absent on an AIP-restore path) instead of throwing an NPE.
        if (liftDate == null) {
            log.warn("No embargo lift date could be determined for Item "
                         + item.getHandle() + ", no policies generated");
            return;
        }
        for (Bundle bn : item.getBundles()) {
            // Skip the LICENSE and METADATA bundles, they stay world-readable
            String bnn = bn.getName();
            if (!(bnn.equals(Constants.LICENSE_BUNDLE_NAME) || bnn.equals(Constants.METADATA_BUNDLE_NAME)
                || bnn.equals(CreativeCommonsServiceImpl.CC_BUNDLE_NAME))) {
                for (Bitstream bs : bn.getBitstreams()) {
                    generatePolicies(context, liftDate.toDate().toLocalDate(), null, bs,
                                     item.getOwningCollection(), terms);
                }
            }
        }
    }

    /**
     * Read the user-supplied embargo terms from the item's metadata, using the
     * same field the embargo subsystem is configured with (embargo.field.terms).
     *
     * @param item the item under embargo
     * @return the terms string, or null if unset
     */
    private String getTermsFromItem(Item item) {
        String termsField = DSpaceServicesFactory.getInstance().getConfigurationService()
                                                 .getProperty("embargo.field.terms");
        if (termsField == null) {
            log.warn("embargo.field.terms is not configured, treating embargo terms as absent");
            return null;
        }
        String[] parts = termsField.split("\\.", 3);
        return ContentServiceFactory.getInstance().getItemService()
            .getMetadataFirstValue(item, parts[0],
                                   parts.length > 1 ? parts[1] : null,
                                   parts.length > 2 ? parts[2] : null,
                                   Item.ANY);
    }

    /**
     * Retained for callers of the parent signature (our setEmbargo() override is
     * the only caller on the normal path). Without the terms there is no way to
     * tell a "Restrict to UW" embargo from a "Delay release" one, so this fails
     * safe: no UW_Users policy is created.
     */
    @Override
    protected void generatePolicies(Context context, LocalDate embargoDate,
                                    String reason, DSpaceObject dso, Collection owningCollection)
        throws SQLException, AuthorizeException {
        generatePolicies(context, embargoDate, reason, dso, owningCollection, null);
    }

    /**
     * Custom embargo application to accomodate UW_Users permission and whether to apply embargo there
     */
    protected void generatePolicies(Context context, LocalDate embargoDate,
                                    String reason, DSpaceObject dso, Collection owningCollection,
                                    String terms)
        throws SQLException, AuthorizeException {

        if (embargoDate == null) {
            return;
        }

        List<Group> authorizedGroups = getAuthorizeService()
            .getAuthorizedGroups(context, owningCollection, Constants.DEFAULT_ITEM_READ);

        // Check if Anonymous group is authorized (it should be, normally)
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
        if (terms != null && terms.contains("Restrict to UW")) {
            // Check if UW_Users group is authorized
            boolean uwUsersGroupIsAuthorized = false;
            Group uwUsers = EPersonServiceFactory.getInstance().getGroupService().findByName(context, "UW_Users");
            UUID idUWUsers = uwUsers.getID();
            for (Group g : authorizedGroups) {
                if (g.getID().equals(idUWUsers)) {
                    uwUsersGroupIsAuthorized = true;
                    break;
                }
            }

            // If the UW_Users group is authorized, add a non-embargoed READ policy for it
            // (it should be authorized, normally)
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
        } else {
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
