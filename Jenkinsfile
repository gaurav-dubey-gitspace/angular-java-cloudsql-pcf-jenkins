pipeline {
	agent any
	tools{maven '3.8.4'}
	stages {
		stage ('Build') {
		
			steps {
				withMaven(maven: '3.8.4') {
					sh 'mvn clean package'
				}
			}
		}
		
		stage ('Deploy') {
		
			steps {
				withCredentials([[$class          : 'UsernamePasswordMultiBinding',
                                  credentialsId   : 'PCF_LOGIN',
                                  usernameVariable: 'USERNAME',
                                  passwordVariable: 'PASSWORD']]) {

//                     sh 'cf login -a https://api.cf.us10.hana.ondemand.com -u $USERNAME -p $PASSWORD'
//                     sh 'cf push'
               }
			}
		
		}
		
		
		
	}
	
	post { 
        always { 
            echo 'post Build!'
		pushToCloudFoundry(
  target: 'https://api.cf.us10.hana.ondemand.com',
  organization: '1a723b59trial',
  cloudSpace: 'testspace',
  credentialsId: 'PCF_LOGIN'
)
        }
    }
}
