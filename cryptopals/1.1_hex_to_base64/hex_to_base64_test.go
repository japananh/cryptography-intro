package hextobase64

import "testing"

func Test_HexToBase64(t *testing.T) {
	type args struct {
		hexStr string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "Test HexToBase64 run successfully",
			args:    args{hexStr: "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"},
			want:    "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
			wantErr: false,
		},
		{
			name:    "Test HexToBase64 run successfully on empty input",
			args:    args{hexStr: ""},
			want:    "",
			wantErr: false,
		},
		{
			name:    "Should throw error on invalid hex string",
			args:    args{hexStr: "ZG9sYW5kCg=="},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HexToBase64(tt.args.hexStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("HexToBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HexToBase64() got = %v, want %v", got, tt.want)
			}
		})
	}
}
