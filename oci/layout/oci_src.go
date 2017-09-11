package layout

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/containers/image/types"
	"github.com/levigross/grequests"
	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

type ociImageSource struct {
	ref        ociReference
	httpClient *http.Client
	descriptor imgspecv1.Descriptor
}

// newImageSource returns an ImageSource for reading from an existing directory.
func newImageSource(ctx *types.SystemContext, ref ociReference) (types.ImageSource, error) {
	descriptor, err := ref.getManifestDescriptor()
	if err != nil {
		return nil, err
	}
	return &ociImageSource{ref: ref, httpClient: &http.Client{}, descriptor: descriptor}, nil
}

// Reference returns the reference used to set up this source.
func (s *ociImageSource) Reference() types.ImageReference {
	return s.ref
}

// Close removes resources associated with an initialized ImageSource, if any.
func (s *ociImageSource) Close() error {
	return nil
}

// GetManifest returns the image's manifest along with its MIME type (which may be empty when it can't be determined but the manifest is available).
// It may use a remote (= slow) service.
func (s *ociImageSource) GetManifest() ([]byte, string, error) {
	manifestPath, err := s.ref.blobPath(digest.Digest(s.descriptor.Digest))
	if err != nil {
		return nil, "", err
	}
	m, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return nil, "", err
	}

	return m, s.descriptor.MediaType, nil
}

func (s *ociImageSource) GetTargetManifest(digest digest.Digest) ([]byte, string, error) {
	manifestPath, err := s.ref.blobPath(digest)
	if err != nil {
		return nil, "", err
	}

	m, err := ioutil.ReadFile(manifestPath)
	if err != nil {
		return nil, "", err
	}

	// XXX: GetTargetManifest means that we don't have the context of what
	//      mediaType the manifest has. In OCI this means that we don't know
	//      what reference it came from, so we just *assume* that its
	//      MediaTypeImageManifest.
	return m, imgspecv1.MediaTypeImageManifest, nil
}

func (s *ociImageSource) getExternalBlob(urls []string) (io.ReadCloser, int64, error) {
	var (
		resp *grequests.Response
		err  error
	)

	cert, err := tls.LoadX509KeyPair("assets/cert/cert.pem", "assets/cert/key.pem")
	if err != nil {
		log.Fatalln("Unable to load cert", err)
	}

	// Load our CA certificate
	clientCACert, err := ioutil.ReadFile("assets/cert/cert.pem")
	if err != nil {
		log.Fatal("Unable to open cert", err)
	}

	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCACert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      clientCertPool,
	}

	tlsConfig.BuildNameToCertificate()

	ro := &grequests.RequestOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		},
	}

	for _, url := range urls {
		resp, err = grequests.Get(url, ro)
		// panic(fmt.Sprintf("%#v", resp.RawResponse))
		if err == nil {
			if resp.StatusCode != http.StatusOK {
				err = errors.Errorf("error fetching external blob from %q: %d", url, resp.StatusCode)
				continue
			}
		}
	}
	if resp.RawResponse.Body != nil && err == nil {
		return resp.RawResponse.Body, getBlobSize(resp.RawResponse), nil
	}
	return nil, 0, err
}

func getBlobSize(resp *http.Response) int64 {
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		size = -1
	}
	return size
}

// GetBlob returns a stream for the specified blob, and the blob's size.
func (s *ociImageSource) GetBlob(info types.BlobInfo) (io.ReadCloser, int64, error) {
	if len(info.URLs) != 0 {
		return s.getExternalBlob(info.URLs)
	}

	path, err := s.ref.blobPath(info.Digest)
	if err != nil {
		return nil, 0, err
	}

	r, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	fi, err := r.Stat()
	if err != nil {
		return nil, 0, err
	}
	return r, fi.Size(), nil
}

func (s *ociImageSource) GetSignatures(context.Context) ([][]byte, error) {
	return [][]byte{}, nil
}
