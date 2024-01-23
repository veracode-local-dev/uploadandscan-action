const core = require('@actions/core');
const appConfig = require('../app-cofig.js');
const { 
  getResourceByAttribute,
  getResource,
  createResource,
}= require('../api/http-requests.js');
const fs = require('fs/promises');
const artifact = require('@actions/artifact');
const { getVeracodePolicyByName } = require('./policy-service.js');
const { getVeracodeTeamsByName } = require('./teams-service.js');
const { runCommand } = require('../api/java-wrapper.js');
const xml2js = require('xml2js');

async function getApplicationByName(vid, vkey, applicationName) {
  core.debug(`Module: application-service, function: getApplicationByName. Application: ${applicationName}`);
  const resource = {
    resourceUri: appConfig().applicationUri,
    queryAttribute: 'name',
    queryValue: encodeURIComponent(applicationName)
  };
  core.debug(resource);
  const response = await getResourceByAttribute(vid, vkey, resource);
  return response;
}

async function getVeracodeSandboxIDFromProfile(vid, vkey, appguid) {
  core.debug(`Module: application-service, function: getSandboxIDfromProfile. Application: ${appguid}`);
  const resource = {
    resourceUri: appConfig().applicationUri+"/"+appguid+"/sandboxes"
  };
  core.debug(resource);
  const response = await getResource(vid, vkey, resource);
  return response;
}

async function createSandboxRequest(vid, vkey, appguid, sandboxname) {
  core.debug(`Module: application-service, function: createSandbox. Application: ${appguid}`);
  const resource = {
    resourceUri: appConfig().applicationUri+"/"+appguid+"/sandboxes",
    resourceData: {
        name: sandboxname
    }
  };
  core.debug(resource);
  const response = await createResource(vid, vkey, resource);
  return response;
}

function profileExists(responseData, applicationName) {
  core.debug(`Module: application-service, function: profileExists. Application: ${applicationName}`);
  if (responseData.page.total_elements === 0) {
    core.debug(`No Veracode application profile found for ${applicationName}`);
    return { exists: false, veracodeApp: null };
  }
  else {
    for(let i = 0; i < responseData._embedded.applications.length; i++) {
      if (responseData._embedded.applications[i].profile.name.toLowerCase() 
            === applicationName.toLowerCase()) {
        return { exists: true, veracodeApp: {
          'appId': responseData._embedded.applications[i].id,
          'appGuid': responseData._embedded.applications[i].guid,
          'oid': responseData._embedded.applications[i].oid,
        } };;
      }
    }
    core.debug(`No Veracode application profile with exact the profile name: ${applicationName}`);
    return { exists: false, veracodeApp: null };
  }
}

async function getVeracodeApplicationForPolicyScan(vid, vkey, applicationName, policyName, teams, createprofile) {
  core.debug(`Module: application-service, function: getVeracodeApplicationForPolicyScan. Application: ${applicationName}`);
  const responseData = await getApplicationByName(vid, vkey, applicationName);
  core.debug(`Check if ${applicationName} is found via Application API`);
  core.debug(responseData);
  const profile = profileExists(responseData, applicationName);
  core.debug(`Check if ${applicationName} has a Veracode application profile`);
  core.debug(profile);
  if (!profile.exists) {
    if (createprofile.toLowerCase() !== 'true')
      return { 'appId': -1, 'appGuid': -1, 'oid': -1 };
    
    const veracodePolicy = await getVeracodePolicyByName(vid, vkey, policyName);
    core.debug(`Veracode Policy: ${veracodePolicy}`)
    const veracodeTeams = await getVeracodeTeamsByName(vid, vkey, teams);
    core.debug(`Veracode Teams: ${veracodeTeams}`);
    // create a new Veracode application
    const resource = {
      resourceUri: appConfig().applicationUri,
      resourceData: {
        profile: {
          business_criticality: "HIGH",
          name: applicationName,
          policies: [
            {
              guid: veracodePolicy.policyGuid
            }
          ], 
          teams: veracodeTeams
        }
      }
    };
    core.debug(`Create Veracode application profile: ${JSON.stringify(resource)}`);
    const response = await createResource(vid, vkey, resource);
    core.debug(`Veracode application profile created: ${JSON.stringify(response)}`);
    const appProfile = response.app_profile_url;
    return {
      'appId': response.id,
      'appGuid': response.guid,
      'oid': appProfile.split(':')[1]
    };
  } else return profile.veracodeApp;
}

async function getVeracodeApplicationScanStatus(vid, vkey, veracodeApp, buildId, sandboxID, sandboxGUID, jarName) {
  core.info(`Module: application-service, function: getVeracodeApplicationScanStatus. Application: ${veracodeApp.appGuid}`);
  core.info(`Veracode App: ${JSON.stringify(veracodeApp)}`)
  core.info(`buildID: ${buildId}`)
  core.info(`sandboxID: ${sandboxID}`)
  core.info(`sandboxGUID: ${sandboxGUID}`)
  core.info(`jarName: ${jarName}`)
  let resource;
  if (sandboxID > 1){
    core.info('Checking the Sandbox Scan Status')
    command = `java -jar ${jarName} -vid ${vid} -vkey ${vkey} -action GetBuildInfo -appid ${veracodeApp.appId} -sandboxid ${sandboxID} -buildid ${buildId}`
    const output = await runCommand(command);
    const outputXML = output.toString();
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(outputXML);
    core.info(`Check results output: ${outputXML}`)
    core.info(`Check results: ${result}`)
    core.info(`Veracode Scan Status: ${result.buildinfo.build.analysis_unit.status}`);
    core.info(`Veracode Policy Compliance Status: ${result.buildinfo.build.policy_compliance_status}`);
    core.info(`Veracode Scan Date: ${result.buildinfo.build.analysis_unit.published_date-result.analysis_unit.published_date_sec}`);
    core.info(`Veracode Policy Compliance Date: ${result.buildinfo.build.published_date}`);

    console.log(`Check results output: ${outputXML}`)
    console.log(`Check results: ${result}`)
    console.log(`Veracode Scan Status: ${result.buildinfo.build.analysis_unit.status}`);
    console.log(`Veracode Policy Compliance Status: ${result.buildinfo.build.policy_compliance_status}`);
    console.log(`Veracode Scan Date: ${result.buildinfo.build.analysis_unit.published_date-result.analysis_unit.published_date_sec}`);
    console.log(`Veracode Policy Compliance Date: ${result.buildinfo.build.published_date}`);
    return {
      'status': result.buildinfo.build.analysis_unit.status,
      'passFail': result.buildinfo.build.policy_compliance_status,
      'scanUpdateDate': result.buildinfo.build.analysis_unit.published_date-result.analysis_unit.published_date_sec,
      'lastPolicyScanData': result.buildinfo.build.published_date
    }
    
  }
  else {
    resource = {
      resourceUri: `${appConfig().applicationUri}/${veracodeApp.appGuid}`,
      queryAttribute: '',
      queryValue: ''
    };
    const response = await getResourceByAttribute(vid, vkey, resource);
    const scans = response.scans;
    for(let i = 0; i < scans.length; i++) {
      const scanUrl = scans[i].scan_url;
      const scanId = scanUrl.split(':')[3];
      if (scanId === buildId) {
        console.log(`Scan Status: ${scans[i].status}`);
        return {
          'status': scans[i].status,
          'passFail': response.profile.policies[0].policy_compliance_status,
          'scanUpdateDate': scans[i].modified_date,
          'lastPolicyScanData': response.last_policy_compliance_check_date
        };
      }
    }
    return { 
      'status': 'not found', 
      'passFail': 'not found'
    };
  }
}

async function getVeracodeApplicationFindings(vid, vkey, veracodeApp, buildId) {
  console.log("Starting to fetch results");
  const resource = {
    resourceUri: `${appConfig().findingsUri}/${veracodeApp.appGuid}/findings`,
    queryAttribute: 'violates_policy',
    queryValue: 'True'
  };
  console.log("APP GUID: "+veracodeApp.appGuid)
  console.log("API URL: "+resource.resourceUri)
  const response = await getResourceByAttribute(vid, vkey, resource);
  const resultsUrlBase = 'https://analysiscenter.veracode.com/auth/index.jsp#ViewReportsResultSummary';
  const resultsUrl = `${resultsUrlBase}:${veracodeApp.oid}:${veracodeApp.appId}:${buildId}`;
  // save response to policy_flaws.json
  // save resultsUrl to results_url.txt
  try {
    const jsonData = response;

    let newFindings = [];
    if (jsonData.page.total_elements > 0) {
      //filter the resutls to only include the flaws that violate the policy
      const findings = jsonData._embedded.findings;
      const fixedSearchTerm = "OPEN"; // Fixed search term
      console.log(findings.length+" findings found");

      console.log("Filtering findings");
      for ( i=0 ; i <= findings.length-1 ; i++ ) {
          if ( findings[i].finding_status.status != fixedSearchTerm ){
              console.log("Finding "+JSON.stringify(findings[i].issue_id)+" is not open and will be ignored");
              console.log("Finding status: "+JSON.stringify(findings[i].finding_status.status));
          }
          else {
              //adding finding to new array
              console.log("Finding "+JSON.stringify(findings[i].issue_id)+" is open");
              console.log("Finding status: "+JSON.stringify(findings[i].finding_status.status));
              newFindings.push(findings[i]);
          }
      }
    }

    //recreate json output
    const links = jsonData._links;
    const page = jsonData.page;
    const filteredJsonData = "{\"_embedded\": {\"findings\": "+JSON.stringify(newFindings, null, 2)+"}, \"_links\": "+JSON.stringify(links, null, 2)+", \"page\": "+JSON.stringify(page, null, 2)+"}";

    //write to file
    await fs.writeFile('policy_flaws.json', filteredJsonData);
    await fs.writeFile('results_url.txt', resultsUrl);
  } catch (err) {
    console.log(err);
  }
  

  const artifactClient = artifact.create()
  const artifactName = 'policy-flaws';
  const files = [
    'policy_flaws.json',
    'results_url.txt',
  ];
  const rootDirectory = process.cwd()
  const options = {
      continueOnError: true
  }
  await artifactClient.uploadArtifact(artifactName, files, rootDirectory, options)
}

module.exports = {
  getVeracodeApplicationForPolicyScan,
  createSandboxRequest,
  getVeracodeSandboxIDFromProfile,
  getVeracodeApplicationScanStatus,
  getVeracodeApplicationFindings
}