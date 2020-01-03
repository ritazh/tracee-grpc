package target

const templSrc = `package target

##################
# Required Hooks #
##################

autoreject_review[rejection] {
  not input.review
  rejection := {}
}

matching_constraints[constraint] {
  constraint := {{.ConstraintsRoot}}[_][_]
}

matching_reviews_and_constraints[[review, constraint]] {
  review := {}
  matching_constraints[constraint] with input as {"review": review}
}

########
# Util #
########

`
