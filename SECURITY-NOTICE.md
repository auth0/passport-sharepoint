---
title: Auth0 Security Bulletin CVE-2019-13483
description: Details about a security vulnerability in Passport-SharePoint 
topics:
 - security
 - security-bulletins
 - authentication
 - passport
contentType:
 - reference
useCase:
 - development
---

# Security Vulnerability in Passport-SharePoint

**Published**: 7/23/2019

**CVE number**: CVE-2019-13483

## Overview

All versions of [Passport-SharePoint](https://github.com/auth0/passport-sharepoint) lower than 0.4.0 do not validate the JWT signature of an access token before processing.

This vulnerability allows attackers to forge tokens and bypass authentication and authorization mechanisms.

## Am I affected?

You are affected by this vulnerability if the following conditions apply:

- You use a version of [Passport-SharePoint](https://github.com/auth0/passport-sharepoint) lower than 0.4.0

## How to fix that?

Developers using the [Passport-SharePoint](https://github.com/auth0/passport-sharepoint) library need to upgrade to the latest version `0.4.0`. Developers should plan to discontinue the use of this library as Auth0 has deprecated the library and it will no longer be maintained.


### Will this update impact my users?

No. This fix patches the library that your application runs, but will not impact your users, their current state, or any existing sessions.
