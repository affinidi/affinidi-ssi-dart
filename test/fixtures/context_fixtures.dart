final context1 = [
  'https://www.w3.org/2018/credentials/v1',
  {
    'NameCredentialPersonV1': {
      '@id': 'https://schema.affinity-project.org/NameCredentialPersonV1',
      '@context': {'@version': 1.1, '@protected': true}
    },
    'data': {
      '@id': 'https://schema.affinity-project.org/data',
      '@context': [
        null,
        {
          '@version': 1.1,
          '@protected': true,
          '@vocab': 'https://schema.org/',
          'NamePerson': {
            '@id': 'https://schema.affinity-project.org/NamePerson',
            '@context': {
              '@version': 1.1,
              '@protected': true,
              '@vocab': 'https://schema.org/',
              'name': 'https://schema.org/name',
              'givenName': 'https://schema.org/givenName',
              'fullName': 'https://schema.org/fullName'
            }
          },
          'PersonE': {
            '@id': 'https://schema.affinity-project.org/PersonE',
            '@context': {
              '@version': 1.1,
              '@protected': true,
              '@vocab': 'https://schema.org/'
            }
          },
          'OrganizationE': {
            '@id': 'https://schema.affinity-project.org/OrganizationE',
            '@context': {
              '@version': 1.1,
              '@protected': true,
              '@vocab': 'https://schema.org/',
              'hasCredential': 'https://schema.org/hasCredential',
              'industry': 'https://schema.affinity-project.org/industry',
              'identifiers': 'https://schema.affinity-project.org/identifiers'
            }
          },
          'Credential': {
            '@id': 'https://schema.affinity-project.org/Credential',
            '@context': {
              '@version': 1.1,
              '@protected': true,
              '@vocab': 'https://schema.org/',
              'dateRevoked': 'https://schema.affinity-project.org/dateRevoked',
              'recognizedBy': 'https://schema.affinity-project.org/recognizedBy'
            }
          },
          'OrganizationalCredential': {
            '@id':
                'https://schema.affinity-project.org/OrganizationalCredential',
            '@context': {
              '@version': 1.1,
              '@protected': true,
              '@vocab': 'https://schema.org/',
              'credentialCategory':
                  'https://schema.affinity-project.org/credentialCategory',
              'organizationType':
                  'https://schema.affinity-project.org/organizationType',
              'goodStanding':
                  'https://schema.affinity-project.org/goodStanding',
              'active': 'https://schema.affinity-project.org/active',
              'primaryJurisdiction':
                  'https://schema.affinity-project.org/primaryJurisdiction',
              'identifier': 'https://schema.org/identifier'
            }
          }
        }
      ]
    }
  }
];

final context2 = [
  'https://www.w3.org/2018/credentials/v1',
  {
    'name': 'http://schema.org/name',
    'degree': 'https://schema.org/educationalCredentialAwarded',
    'university': 'https://schemas.org/educationalInstitution'
  }
];

final context3 = [
  'https://www.w3.org/2018/credentials/v1',
  {
    'schema': 'http://schema.org/',
    'ex': 'https://example.org/terms/',
    'person': {
      '@context': {'name': 'schema:name', 'birthDate': 'schema:birthDate'}
    },
    'education': {
      '@context': {
        'degree': 'schema:educationalCredentialAwarded',
        'alumniOf': 'schema:alumniOf'
      }
    }
  }
];
