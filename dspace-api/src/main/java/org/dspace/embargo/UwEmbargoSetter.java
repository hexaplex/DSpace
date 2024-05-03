package org.dspace.embargo;

import java.sql.SQLException;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.dspace.core.LogManager;

import org.dspace.authorize.AuthorizeException;
import org.dspace.authorize.AuthorizeManager;
import org.dspace.authorize.ResourcePolicy;
import org.dspace.content.DCDate;
import org.dspace.content.Item;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.core.Constants;
import org.dspace.content.DSpaceObject;
import org.dspace.content.Collection;
import org.dspace.eperson.Group;

//import org.dspace.content.*;


// Extends DayTableEmbargoSetter to handle whether to apply embargo to UW_Users group permission

public class UwEmbargoSetter extends DayTableEmbargoSetter
{
    /** log4j logger */
    private static Logger log = Logger.getLogger(UwEmbargoSetter.class);
    private String lastTerms = null;

    /**
     * Override parseTerms solely to set lastTerms for use by generatePolicies() 
     */
    public DCDate parseTerms(Context context, Item item, String terms)
        throws SQLException, AuthorizeException, IOException {

        lastTerms = terms;
        return super.parseTerms(context, item, terms);
    }


    /**
     * Custom embargo application to accomodate UW_Users permission and whether to apply embargo there
     */
    protected void generatePolicies(Context context, Date embargoDate,
                                    String reason, DSpaceObject dso, Collection owningCollection) throws SQLException, AuthorizeException {

        // add only embargo policy
        if (embargoDate!=null) {

            Group[] authorizedGroups = AuthorizeManager.getAuthorizedGroups(context, owningCollection, Constants.DEFAULT_ITEM_READ);

            // This should always be true, as UW doesn't apply embargos to collections that are not public-access.  Left here anyways just in case
            // look for anonymous
            boolean isAnonymousInPlace=false;
            for (Group g : authorizedGroups) {
                if (g.getID()==Group.ANONYMOUS_ID ) {
                    isAnonymousInPlace=true;
                    break;
                }
            }

            // Embargo anonymous group
            if (isAnonymousInPlace) {
                // Anonymous group is always group id "0"
                ResourcePolicy rp = AuthorizeManager.createOrModifyPolicy(null, context, null, 0, null, embargoDate, Constants.READ, reason, dso);
                if (rp!=null){
                    rp.update();
                }
            }

            // If embargo also applies to UW_Users, apply embargo there, too
            if (!lastTerms.contains("Restrict to UW")) {

                // look for UW_Users
                boolean isUWUsersInPlace=false;
                Group uwUsers = Group.findByName(context, "UW_Users");
                int idUWUsers = uwUsers.getID();
                for(Group g : authorizedGroups) {
                    if(g.getID()==idUWUsers) {
                        isUWUsersInPlace=true;
                        break;
                    }
                }

                // Embargo UW_Users
                if(isUWUsersInPlace) {
                    log.info("Applying embargo to UW_Users"); 
                    ResourcePolicy rp = AuthorizeManager.createOrModifyPolicy(null, context, null, idUWUsers, null, embargoDate, Constants.READ, reason, dso);
                    if (rp!=null) {
                        rp.update();
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
}