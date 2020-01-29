package oracle

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/ovalutil"
)

const (
	OracleLinux5Platform = "Oracle Linux 5"
	OracleLinux6Platform = "Oracle Linux 6"
	OracleLinux7Platform = "Oracle Linux 7"
	OracleLinux8Platform = "Oracle Linux 8"
)

// a mapping between oval platform string to claircore distribution
var platformToDist = map[string]*claircore.Distribution{
	OracleLinux5Platform: fiveDist,
	OracleLinux6Platform: sixDist,
	OracleLinux7Platform: sevenDist,
	OracleLinux8Platform: eightDist,
}

var _ driver.Parser = (*Updater)(nil)

func (u *Updater) Parse(ctx context.Context, r io.ReadCloser) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "oracle/Updater.Parse").
		Logger()
	ctx = log.WithContext(ctx)
	log.Info().Msg("starting parse")
	defer r.Close()
	root := oval.Root{}
	if err := xml.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("oracle: unable to decode OVAL document: %w", err)
	}
	log.Debug().Msg("xml decoded")

	vulns := make([]*claircore.Vulnerability, 0, 250000)
	pkgcache := map[string]*claircore.Package{}
	for _, def := range root.Definitions.Definitions {
		// search for a platform tag that maps to a distribution
		// oracle will always have a single well defined platform tag
		var dist *claircore.Distribution
	DistSearch:
		for _, affected := range def.Affecteds {
			for _, platform := range affected.Platforms {
				if d, ok := platformToDist[platform]; ok {
					dist = d
					break DistSearch
				}
			}
		}
		if dist == nil {
			// we searched for a platform string
			// and couldn't map one. continue to next
			// definition
			continue
		}
		// create a prototype vuln which we will
		// create copies of.
		protoVuln := &claircore.Vulnerability{
			Updater:     u.Name(),
			Name:        def.Title,
			Description: def.Description,
			Links:       ovalutil.Links(def),
			Severity:    def.Advisory.Severity,
			Dist:        dist,
		}
		// recursively collect criterions for this definition
		cris := []*oval.Criterion{}
		walkCriterion(ctx, &def.Criteria, &cris)
		// unpack criterions into vulnerabilities
		for _, criterion := range cris {
			// lookup test
			_, index, err := root.Tests.Lookup(criterion.TestRef)
			if err != nil {
				log.Debug().Str("test_ref", criterion.TestRef).Msg("test ref lookup failure. moving to next criterion")
				continue
			}
			test := root.Tests.RPMInfoTests[index]
			if len(test.ObjectRefs) != len(test.StateRefs) {
				log.Debug().Str("test_ref", criterion.TestRef).Msg("object refs and state refs are not in pairs. moving to next criterion")
				continue
			}
			// look at each object,state pair the test references
			// and create a vuln if an evr tag if found
			for i := 0; i < len(test.ObjectRefs); i++ {
				objRef := test.ObjectRefs[i].ObjectRef
				stateRef := test.StateRefs[i].StateRef
				_, objIndex, err := root.Objects.Lookup(objRef)
				if err != nil {
					log.Debug().Str("object_ref", objRef).Msg("failed object lookup. moving to next object,state pair")
					continue
				}
				_, stateIndex, err := root.States.Lookup(stateRef)
				if err != nil {
					log.Debug().Str("state_ref", stateRef).Msg("failed state lookup. moving to next object,state pair")
					continue
				}
				object := root.Objects.RPMInfoObjects[objIndex]
				state := root.States.RPMInfoStates[stateIndex]
				// if EVR tag not present this is not a linux package
				// see oval definitions for more details
				if state.EVR == nil {
					continue
				}
				// copy prototype
				vuln := *protoVuln
				if pkg, ok := pkgcache[object.Name]; !ok {
					p := &claircore.Package{
						Name: object.Name,
					}
					pkgcache[object.Name] = p
					vuln.Package = p
				} else {
					vuln.Package = pkg
				}
				vuln.FixedInVersion = state.EVR.Body
				vulns = append(vulns, &vuln)
			}
		}
	}
	return vulns, nil
}

// walkCriterion recursively extracts Criterions from a root Crteria node in a depth
// first manor.
//
// a pointer to a slice header is modified in place when appending
func walkCriterion(ctx context.Context, node *oval.Criteria, cris *[]*oval.Criterion) {
	// recursive to leafs
	for _, criteria := range node.Criterias {
		walkCriterion(ctx, &criteria, cris)
	}
	// search for criterions at current node
	for _, criterion := range node.Criterions {
		c := criterion
		*cris = append(*cris, &c)
	}
}
