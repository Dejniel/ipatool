# GrandSlam References

The SRP formulas, SPD decryption, protocol flow and independent synthetic
test vectors are adapted from `blacktop/ipsw` at
`cf37896883e8484aa9af171fd6bbbbeef981ea85`:

- https://github.com/blacktop/ipsw/blob/cf37896883e8484aa9af171fd6bbbbeef981ea85/internal/srp/grandslam.go
- https://github.com/blacktop/ipsw/blob/cf37896883e8484aa9af171fd6bbbbeef981ea85/internal/srp/grandslam_test.go
- https://github.com/blacktop/ipsw/blob/cf37896883e8484aa9af171fd6bbbbeef981ea85/internal/storeauth/grandslam.go

Phone selection follows Apple's JSON `/auth` and `/auth/verify/phone` flow,
also implemented by https://github.com/biemster/FindMy/blob/main/pypush_gsa_icloud.py.
Unlike clients that assume phone ID 1, this module requires an explicit choice
from the returned numbers and never guesses the delivery destination.

## MIT License

Copyright (c) 2018-2026 blacktop
Copyright 2013-2017 Sudhi Herle <sudhi.herle-at-gmail-dot-com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
