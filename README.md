##Web Development - Wiki Page

###Course Project
School: Udacity

Course: Web Development

###Project Description
You will build your own wiki that a user can sign into and can post articles to.

In order to be graded correctly for this project, there are a few things to keep in mind. We'll be grading your web app by signing in to your wiki, then trying to create and edit random pages. Therefore, any path we choose should either:

Go to that page if it has already been created.
Redirect to an edit page if that page doesn't yet exist, assuming the user is signed in.
The only static url we'll be requiring for this part is that the url for users to signup is at:

signup_url = url + "/signup"

Where 'url' is the url that you have entered in the text box above. In order to edit the page, we require you to have a form with a single textfield, 'content', containing the content of the page to be edited.
